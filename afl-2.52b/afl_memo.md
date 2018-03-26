### American Fuzzy Lopのソースコード解析
ここ最近のAmerican Fuzzy Lopに対してオレオレ実装した過程でソースコードを解析したので、その結果をブログにまとめてみようということで書いてみました。ソースコードの解析しているようなブログなどはとくにみたことがない(2018/03/19時点)ので書く価値があるのかなという自己満足で書いてみました

### American Fuzzy Lopとは
American Fuzzy LopはGoogleのエンジニアである、Michal Zalewski氏らによるfuzzing toolである。fuzzingとはざっくりいうと「自動でバグ、脆弱性を見つけようぜ」というものである。<br>

有名なところで言うとCGC(Cyber Grand Challenge)でコンピュータ同士の攻防でfuzzingが使われていたりする。またここ最近の出来事としては2017年のプレスリリースされたMicrosoftの[Security Risk Detection](https://www.microsoft.com/en-us/security-risk-detection/)というものがある。これは[Neural fuzzing: applying DNN to software security testing](https://www.microsoft.com/en-us/research/blog/neural-fuzzing/)にかかれている通りfuzzingのアルゴリズムにDeep Neual Networkを適応させている。

つまり、「自動でバグや脆弱性を見つけるサービスをはじめました」ということである。有名な企業がこういったことをやっているくらいホットな話題なので興味があるのであれば、ぜひこれをスタートアップとして、fuzzingに取り組んでほしい。

### American Fuzzy Lopのアルゴリズムについて
Amrican Fuzzy Lopのアルゴリズムは遺伝的アルゴリズムである。もっと簡単に言うと「testするものが実行速度が速くて、カバー範囲(様々な条件分岐に対応している)が広くて、より深く(条件分岐の先の先)までtestすることができるのが良いcase」という考えのもとで実装がされている。<br>

American Fuzzy Lopとしては「とにかく速く、正確に、より多くの不要な部分（不要なライブラリでCPUを多く使うなど）を除き、シンプルなソースコードである」というのをコンセプトとしている。

### American Fuzzy Lopの変異戦略について
変異戦略とは、ユーザーが用意した初期値を様々な方法で変化させていく方法である。大きく分けて以下の6つある。<br>
- SIMPLE BITFLIP(xor戦略)<br>
- ARITHMETIC INC/DEC(数字加算/数字減算戦略)<br>
- INTERESTING VALUES(固定値を挿入する戦略)<br>
- DICTIONARY STUFF(辞書型のdataを挿入する戦略)<br>
- RANDOM HAVOC(ランダムに用意された戦略を選ぶ戦略)<br>
- SPLICING(dataをspliteする戦略)<br>

今回はこの6つのすべてをソースコード(afl-fuzz.cのfuzz_one関数)を用いながら詳しく、よりシンプルに説明をしていく。<br>

### 戦略に入る前処理(不要なdataのskip)
実際に戦略に入る前に最小限のfuzzingをするために不必要な部分のdata(queue)を取り除いていく。取り除かれるdataは以下の3つになる。<br>
- 戦略処理を待っているエラーを見つけるようなdata(pending_favored)があれば、そのdataがすでにfuzzingされているdata(already-fuzzed)または、エラーを起こすような変化がないdata(non-favored)であった場合は99％の確率で戦略を起こさずにreturnする。<br>
- penging_favoredがない場合は、fuzzingを実行するときのoptionでdumb_mode（ユーザーの初期値のみでfuzzingを行うmode,私の中ではアホの子modeとよんでいる）ではない、現在のdataがエラーを見つけるようなdata(favored queue)ではない、戦略処理を待っているqueueの数(queue_paths)が10個よりも少ない。という3つの条件が揃った時に以下の2つの条件にいく<br>
    - queue_pathsされているものを1周した時に加算される数(queue cycle)が1周より上、すでにfuzzingされているqueueの2つの条件があっていれば75％の確率で戦略を起こさずにreturnする。<br>
    - それ以外の条件であれば95%の確率で戦略を起こさずにreturnする。<br>

以下はそのソースコードに当たる部分である。<br>
```c
#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1) return 1;

#else

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */
// already-fuzzed と non-favoredはskipする
    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {//pending_favoredがないときこちらの条件を比べる

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {//lower for never-fuzzed entries.

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;//75%の確率でreturn

    } else {//higher for already-fuzzed

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;//95%の確率でreturn

    }

  }

#endif /* ^IGNORE_FINDS */
```

### 戦略に入る前処理(CALIBRATIONを失敗しているdataであるとき)
- CALIBRATIONとは、実際にdata(queue)を使って実行ファイルを走らせ、そのqueueのカバー範囲、実行速度、どのようなエラーになるかなどを記録する関数である。<br>
- これからcalibrate_case関数の説明をしていく。<br>
- fuzz_one関数に入る前の段階でcalibration関数は実行されており、失敗するようなflag(cal_failed)が立つのは関数が実行され始めてすぐの部分である。<br>
- デフォルトの状態(dumb_modeではない状態)であればinit_forkserverを使って子プロセスを生成する。<br>
- write_to_testcaseで.cur_input fileにdataの内容を書き込む。<br>
- 書き込んだあと、run_target関数で子プロセスの方で実行ファイルをexecvで実行して、その実行結果を親プロセスに返す。<br>
- stageは全部で8回(fast calibrationのflagが立っていない時)行われる。つまり、run_targetは全部で8回行われる。<br>
- run_targetが終わるたびにカバー範囲(trace_bits)を使ってhashを生成する。<br>
- hashは一番最初にrun_targetを実行した時のhashを現在のqueueに保存したあとに、最初のカバー範囲をfirst_traceに入れて後のstageと比べる<br>
- 2回目以降に生成したhashが一番最初のhashと違っていた場合、新しいinputの組み合わせ(new tuple)で、新たなカバー範囲を見つけたので全体のカバー範囲(virgin_bits)の更新を行う<br>
- first traceとtrace bitsを比べていき、一致しなかったらその部分に変化があった場所(var_bytes)としてflagを立てる。<br>
- update_bitmap_score関数で現在のqueueが現時点で最も優れているqueue(top_rated)と比べて実行時間とdataの長さを掛けた数よりも小さかったらtop_ratedと入れ替える。<br>
- もしなかった場合はtop_ratedに現在のqueueを入れる。<br>
- queueに変化があった場所(var_bytes)があったというflagを立てる。<br>
以下に戦略に入る前処理(CALIBRATIONを失敗しているdataであるとき)を載せておく。cliburation関数の方は公開したコメント付きソースコードでみてほしい。<br>
```c
/*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {// 3より小さい場合のみcalibrate_case関数を実行

      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR)
        FATAL("Unable to execute target application");

    }

    if (stop_soon || res != crash_mode) {
      cur_skipped_paths++;// 現在のqueueをスキップしたのでスキップした数を増やす
      goto abandon_entry;
    }

  }
```
### 戦略に入る前処理(dataの最小限までのtrimming)
- trimとはdataの振る舞いに影響を与えない最小限のdataのtrimmingをおこなうものである。trim_case関数で行われる。これからtrim_case関数の説明をしていく。<br>
- trim_caseではdataを16で割り、1024まで2ずつ割っていく。このとき、run_target関数を実行して、hashが変わったかを比べて変わっていたらcalibration関数と同様にupdate_bitmap_scoreを更新するが、割り切れるまでループを抜けないので現在のtrace_bitsをclean_traceに保存する。<br>
- 割り切れる最小値まで割り続けるので必然的に「カバー範囲(trace_bits)に変化があった最小値の長さ」まで割られる。<br>
以下にtrimmingの部分のソースコードを載せておく。trim_caseの部分は公開したコメント付きソースコードを見てほしい<br>
```c
  /************
   * TRIMMING *
   ************/

  if (!dumb_mode && !queue_cur->trim_done) {

    u8 res = trim_case(argv, queue_cur, in_buf);// queueをtrimして実行させる

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon) {
      cur_skipped_paths++;//放棄した数を増やす
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */
// 失敗していたとしてもtrim_done flagをたてる
    queue_cur->trim_done = 1;

    if (len != queue_cur->len) len = queue_cur->len;//trimmingしてqueueの長さが違っていたら変更する

  }

  memcpy(out_buf, in_buf, len);//trimされているのであればdataの更新を行う(trimされていなかったら値は変わっていない)
```
### 戦略に入る前処理(dataの点数付け)
- preformance scoreはqueueの点数付けを行う部分である。calculate_score関数で点数をつける。これからcalculate_score関数の説明をしていく。<br>
- scoreが良くなる条件は4つある。<br>
- 1つ目は平均実行時間よりも少なければ少ないほど良いscoreになる。<br>
- 2つ目はcover範囲が広ければ広いほど良いscoreになる。<br>
- 3つ目はqueue cycleの回数が高ければ高いほど良いscoreにする。これはqueueが多く実行されればされるほど変異を様々なtupleで行われエラーを見つけやすくなるためである。<br>
- 4つ目はより深く条件分の先の先(depth)までいくqueueは良いscoreになる。<br>
- calculate_scoreが終わって、変異戦略をskipする(正確にはRANDOM HAVOCまでgoto)条件として -d optionがある、すでにfuzzingされているもの(was_fuzzed)、過去にfuzzingした(resume)favored pathとしてqueue(passd_det)が残っている。(American Fuzzy Lopはoutputディレクトリに過去に中断したdata(queue)を記録しているため、それを使って再び途中から実行させることができる機能を持っている。このdataをresume queueという。20分以上実行した形跡があるのであればfuzzingを最初から実行させようとすると初期化の段階で警告文が出て実行が中断される)の3つの条件のうちどれかに当てはまるとskipする。<br>
- skipしなかった場合はこれから全部の戦略を実行しますflag(doing_det)を立てる。
以下はそのソースコードに当たる部分である。calculate_score関数は公開したコメント付きソースコードを見てほしい<br>
```c
  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);//queueのscoreをつける

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;

  doing_det = 1;//deterministic fuzzing flagを立てる
```
### SIMPLE BITFLIP(xor戦略)<br>
- SIMPLE BITFLIPでは、bit単位のxor、byte単位でのxorの2つの戦略でqueueを変異させていく。<br>
まずは、bit単位のxorの説明をしていく。
- bit単位のxorでは3つの段階にわけられてqueueを変異させていく。<br>
- 最初の段階では1byteを1つの部分に対して、0x80でstage数に合わせて右にbitシフトさせてxorをしていく。<br>
- 2段階目では1byteを2つの部分に対して、0x80でstage数に合わせて右にbitシフトさせてxorをしていく。<br>
- 3段階では1byteを4つの部分に対して、0x80でstage数に合わせて右にbitシフトさせてxorをしていく。<br>
基本的には処理は3つとも同じであるため、最初の段階のSingle walking bitだけを説明する。<br>
- stageごとに、common_fuzz_stuff関数が実行されてrun_target関数が実行される。run_targetの戻り値として返ってきた実行結果(fault)をsave_if_interesting関数を使って振り分ける。これからsave_if_interesting関数の説明をする。<br>
- save_if_interesting関数を開始してすぐに-C option(crash_mode)の場合の処理に入る。今回はデフォルトの処理の説明をこれからしていく。<br>
- switch文でFAULT_TMOUT、FAULT_CRASHでfaultの内容が振り分けられる。<br>
  - FAULT_TMOUTのとき、実行ファイルはtime outエラーを起こして終了している。<br>
    - time outを起こして終了した全体の数(total_tmouts)を加算する。<br>
    - simplify_trace関数を使ってtrace_bitsのnot hit、hit(それぞれ0x01、0x80でマークされている)のマークづけを行う。<br>
    - has_new_bitsを使って、trace_bitsとvirgin_tmout(time out error用の全体のカバー範囲)を比べて、見たことがないtime out(hit countの変更とnew tuple)がなければreturnをする<br>
    - unique time outの数を増やす(unique_tmouts)<br>
    - もし、ユーザーが設定したtime outが小さい場合はもう一度hang_tmout(1000ms)でrun_target関数を走らせる。<br>
    - FAULT_CRASHであればFAULT_CRASHの処理にいく。FAULT_TMOUTであれば何もしないでreturnする。<br>
  -  FAULT_CRASHのとき、実行ファイルはSEGVエラーを起こして終了している。<br>
    - 処理はFAULT_TMOUTと変わらないため省略
- (common_fuzz_stuff関数を抜けると)stageが8の倍数 - 1(8byte単位)とき、hashを生成して、それぞれの段階で自動辞書型(a_extras)の生成を行う<br>
  - 現在のstageが一番最後かつ、cksumとprev_cksum(前回のチェックサム)が一致するときは次の処理に入る。<br>
    - out_bufの一番最後の文字をa_collectに入れる。<br>
    - a_len(a_collectの長さ)の長さが3以上32以下であれば、maybe_add_auto関数を実行して自動辞書型(a_extras)の生成を行う<br>
  - cksumとprev_cksum(前回のチェックサム)が一致しないとき<br>
    - a_len(a_collectの長さ)の長さが3以上32以下であれば、maybe_add_auto関数を実行して自動辞書型(a_extras)の生成を行う<br>
    - prev_cksumをcksumに更新する。<br>
  - 現在のqueueのcksumと生成したcksumを比べて一致しなかった場合<br>
    - a_len(a_collectの長さ)の長さが32より下であれば、out_bufの一番最後の文字をa_collectに入れる。a_lenを加算する。<br>
- ループ処理を抜けるとSingle walking bitで見つけた、条件分岐先(queued_paths)、実行エラー(unique_crashes)を加算する。<br>
以下はそのソースコードに当たる部分である。save_if_interesting関数、simplify_trace関数、common_fuzz_stuff関数、maybe_add_auto関数、2段階目、3段階目は公開したコメント付きソースコードを見てほしい<br>
```c
  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 3;// len * 2^3した値(bit単位)をstage_maxにする
  stage_name  = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;//実行してtime outとskip flagがあればgoto

    FLIP_BIT(out_buf, stage_cur);
       .
       .
       .

    if (!dumb_mode && (stage_cur & 7) == 7) {//stage_curが7の倍数であれば

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);//out_bufの1byteを追加最後のステージなのでa_lenの初期化はない

      } else if (cksum != prev_cksum) {//前回とチェックサムが違った場合

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

        a_len = 0;//addしたのでa_lenを初期化
        prev_cksum = cksum;//チェックサムの更新

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
        a_len++;

      }

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;//stage_flip1でみつけたpathとcrashesの数を加算
  stage_cycles[STAGE_FLIP1] += stage_max;//stageを実行した回数を加算
```
次にbyte単位のxorの説明をしていく。<br>
- byte単位でのxorでは1byte単位、2bytes単位、4bytes単位の3つでqueueを変異させていく。<br>
- 今回は1byte単位の説明だけをしていく。<br>
- ループに入ったすぐにout_bufの1byteを0xffで反転する。<br>
- common_fuzz_stuff関数でrun_target関数で実行ファイルを走らせる。<br>
- stageごとに変更を加えた場所にマーク付けを行う(eff_map)部分にマーク付けが行われていなかった場合<br>
  - dataの長さが128byte以上であればhashの生成を行う(ただし、dumb_modeでないとき)<br>
  - それ以外の時はqueueに保存されているチェックサムを反転させた値をcksumに入れる。<br>
  - cksumとqueueに保存されているチェックサムが違った場合eff_mapにマーク付けを行い、eff_mapにマーク付けされている数(eff_cnt)を増やす。<br>
- 反転させていたoutbufの1byteを元に戻す。<br>
- ループを抜けてすぐに、eff_mapにマーク付けされている数が90％以上あれば、lenを8byte単位にした状態でeff_mapの先頭からマーク付けを行う。<br>
- 8byteごとにマーク付けを行った数(blocks_eff_select)だけ加算する。<br>
- 全体の8byteごとにマーク付けを行った数(blocks_eff_total)を加算する<br>
1byte単位のxorの部分だけのソースコードを載せる。残りの部分は公開したソースコードで確認してほしい。<br>
```c
  /* Walking byte. */

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;//1byte反転させる

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)]) {//現在のstageがeff_mapになかった場合

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);// 現在のqueueの長さが128byte以上であったら
      else
        cksum = ~queue_cur->exec_cksum;//128byte以上ではない場合はチェックサムを反転させたものを生成

      if (cksum != queue_cur->exec_cksum) {//128byte以上で生成したチェックサム、反転させたqueueのチェックサムがqueueのチェックサムと違った場合、eff_mapに現在のstageのflagをつける
        eff_map[EFF_APOS(stage_cur)] = 1;
        eff_cnt++;
      }

    }

    out_buf[stage_cur] ^= 0xFF;//元に戻す

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */
//密集している数が90％より上であれば
  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {//lenの8byte単位の個数とlen AND 0x03の値(lenが1byteから7byte用)を足した値をeff_cntと比べるかつ、

    memset(eff_map, 1, EFF_ALEN(len));//8byte単位にアラインメントしたものをeff_mapの先頭から埋めていく

    blocks_eff_select += EFF_ALEN(len);//埋めた数だけ加算する

  } else {

    blocks_eff_select += eff_cnt;//それ以外であれば現在のeff_cntを加算する

  }

  blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;
```
### ARITHMETIC INC/DEC(数字加算/数字減算戦略)<br>
ここでの戦略では、1から35までの数字を順番に加算・減算をやっていく。<br>
- 加算と減算は8bit、16bit、32bitの3つの方法で行われる。<br>
- eff_mapにマーク付けがされていないところでは、この戦略は行わない。<br>
- 前回の戦略であるbitflipができなかったものに対して(could_be_bitflip関数を使って判断をする)、この戦略を行っていく。<br>
- できなかったものに対してやる理由は、前戦略でのbitflipと同じdataを実行しないようにするためである。<br>
- 16bit、32bitはlittle endianとbig endianを考慮した戦略になっている。<br>
今回は、16bitでの説明をしていく。<br>
- dataの長さが、2byteない状態であればARITHMETIC INC/DEC戦略をskipする。<br>
- stage_max(ループを行う最大回数)は加算、減算のlittle endian用と加算、減算のbig endian用の4つを最大回数に設定をする。<br>
- out_bufを2byteずつorigに入れて、eff_mapに連続でマーク付けを行われているかを確認する。マークづけされていなければskipする。<br>
- マークされている場合、ARITHMETIC(1から35)までを順番にlittle endianとbig endianの加算と減算を行っていく。<br>
- 最初はlittle endian<br>
  - 加算するときにoverflowを起こしていないかをチェックしたあとに、could_be_bitflip関数を使ってbitflipができないことを確認する。これらの条件を突破したらcommon_fuzz_stuff関数を実行する。<br>
  - 減算するときにunderflowを起こしていないかをチェックしたあとに、could_be_bitflip関数を使ってbitflipができないことを確認する。これらの条件を突破したらcommon_fuzz_stuff関数を実行する<br>
- out_bufを元に戻す。<br>
- 次はbig endian<br>
  - 処理はlittle endianと変わらない。<br>
  - 変わるのはSWAP関数を使ってbig endianにするくらい。<br>
以下は、16bitの戦略部分である。その他の部分は公開したソースコードを確認してほしい。<br>
```c
 if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;//4はINC/DECのlittle endianとBig endian用

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {
//SWAP16はlittle endian対策下位1byteと上位1byteを入れ替える(big endian用)
      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {//orig(2byte)を0xff(下位1byteがlittle endianなので上位にくる)と比べてoverflowしていないかチェックをする

        stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;
 
      } else stage_max--;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {//underflowチェックを行う下位1byteがjよりも小さかったら

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;//次はbig endianにして考える


      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

```
### INTERESTING VALUES(固定値を挿入する戦略)<br>
INTERESTING VALUESは、固定値を挿入するような戦略で、8bit,16bit,32bitの戦略で、それぞれの大きさでoverflow、underflow、off-by-one、比較するときにミスしそうな値を使ってfuzzingを行うようなものである。<br>
- eff_mapにマーク付けがされていないところでは、この戦略は行わない。<br>
- 前回の戦略であるbitflip, arithmetic, interesting(自身の処理よりも小さい大きさの戦略、自分自身)ができなかったものに対して(could_be_bitflip関数、could_be_arith関数、could_be_interest関数を使って判断をする)、この戦略を行っていく。<br>
- できなかったものに対してやる理由は、前戦略と同じdataを実行しないようにするためである。(無駄を省く)<br>
- 16bit、32bitはlittle endianとbig endianを考慮した戦略になっている。<br>
今回は、16bitでの説明をしていく。また、little endianとbig endianの処理はSWAP関数を使うかどうかなのでlittle endianの部分のみを説明する<br>
- dataの長さが、2byteない状態であれば戦略INTERESTING VALUESをskipする。<br>
- stage_max(ループを行う最大回数)はlittle endian用とbig endian用の2つを最大回数に設定をする。<br>
  - out_bufを2byteずつorigに入れて、eff_mapに連続でマーク付けを行われているかを確認する。マークづけされていなければskipする。<br>
  - マーク付けがされている場合、前回の戦略であるbitflip, arithmetic, interestingと同じではないことを確認して、同じであればskip<br>
  - 同じではなかった場合はcommon_fuzz_stuff関数を実行する。<br>
- out_bufを元に戻す。<br>
以下は、16bitの戦略部分である。その他の部分は公開したソースコードを確認してほしい。<br>
```c
  /* Setting 16-bit integers, both endians. */

  if (no_arith || len < 2) goto skip_interest;

  stage_name  = "interest 16/8";
  stage_short = "int16";
  stage_cur   = 0;
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);//little endian and big endian用

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= sizeof(interesting_16);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {//origが3つともにあてはまらないものだけ

        stage_val_type = STAGE_VAL_LE;//現在のstageをlittle endianであることにする

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;
// big endian用
      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u16*)(out_buf + i) = orig;//元に戻す

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;
```
### DICTIONARY STUFF(辞書型のdataを挿入する戦略)<br>
DICTIONARY STUFFは全部で3つの戦略を行う。
- ユーザー側で用意した辞書型のdataを使ってout_bufをoverwriteする戦略 
- ユーザー側で用意した辞書型のdataを使ってout_bufを連結、挿入する戦略
- 自動で生成した辞書型のdataを使ってout_bufをoverwriteする戦略
ただし、ユーザー側で用意した辞書型の数(extras_cnt)、自動で生成した辞書型の数(a_extras_cnt)が0であればこれらの戦略はそれぞれskipする。(基本的にユーザー側で辞書型の初期値を用意していない限りこれらの戦略は行われない)<br>
まず最初に、ユーザー側で用意した辞書型のdataを使ってout_bufをoverwriteする戦略の説明からしていく。<br>
- ループ処理はout_bufのlenの大きさが最大回数とする。つまり、out_bufの先頭からユーザー側で用意した辞書型のdataを使ってout_bufをoverwriteする。<br>
  - 次のループ処理はユーザー側で用意した辞書型の数を最大回数とする。辞書型は予め、size順にソートされている。(初期化の段階のload_extras関数の部分でソートされる)<br>
    - extras_cntが200超えていたとしても、extras_cntを使ってランダム化(URとdefineされている)させて、200より低かった場合<br>
    - 辞書型のlenがout_bufのlenよりも大きい時<br>
    - out_bufと同じ値<br>
    - eff_mapにextrasの長さ分末尾から探した時にflagが一つでも立っていない時<br>
  この4つの条件に当てはまるとループをcontinue<br>
  4つの条件に当てはまらなかった場合、out_bufをユーザー側で用意した辞書型のdataを使って上書きを行い、common_fuzz_stuff関数を実行する。成功したらstage_curを増やす。
- out_bufをin_bufを使って上書きした部分を元に戻し、次のループにいく。<br>
以下は、該当部分のソースコードである。その他の部分は公開したソースコードを確認してほしい。<br>
```c
  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  stage_name  = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */
// extras_cntが200超えていたとしても、extras_cntを使ってランダム化させて、200より低かった場合は次の条件に行く
// 辞書型のlenがout_bufのlenよりも大きい時、out_butと同じ値、eff_mapにextrasの長さ分末尾から探した時にflagが一つでも立っていない時、の3つのうちどれかに、あてはまった時はスキップ
      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);//元に戻す

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UO] += stage_max;

```
次に、ユーザー側で用意した辞書型のdataを使ってout_bufを連結、挿入する戦略の説明を行う。<br>
- len + 128byte(ex_tmp)分のallocateを行う。
- ループ処理はout_bufのlenの大きさが最大回数とする。つまり、out_bufの先頭からユーザー側で用意した辞書型のdataを使ってout_bufに対して挿入をする。<br>
  - 次のループ処理はユーザー側で用意した辞書型の数を最大回数とする。辞書型は予め、size順にソートされている。(初期化の段階のload_extras関数の部分でソートされる)<br>
    - len + extrasの長さが1KBよりも大きい場合はskip(小さい場合は以下に進む)<br>
    - ex_tmpにextrasをコピーする。<br>
    - extrasを挿入した後ろにout_bufを挿入する。(ループが進むにつれて、挿入する内容がout_bufの先頭から一つずつずれていく)<br>
    - common_fuzz_stuff関数を実行する<br>
    - stage_curを加算する<br>
  - ex_tmpにout_bufのアドレスを代入する。(ループが進むに連れてex_tmpの先頭からout_bufに変わっていく)<br>
```c
  /* Insertion of user-supplied extras. */
//ユーザーが用意したfileのdata + out_bufを直接全て入れるやつ
  stage_name  = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i <= len; i++) {

    stage_cur_byte = i;

    for (j = 0; j < extras_cnt; j++) {

      if (len + extras[j].len > MAX_FILE) {//1KBを超えていない時
        stage_max--; 
        continue;
      }

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);//先にextrasをコピー

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);//out_bufを後ろにつける

      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
        ck_free(ex_tmp);
        goto abandon_entry;
      }

      stage_cur++;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];//out_bufをex_tmpの先頭につける(ループが進むに連れてex_tmpの先頭からout_bufに変わっていく)

  }

  ck_free(ex_tmp);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;

```
自動で生成した辞書型のdataを使ってout_bufをoverwriteする戦略の説明は、最初に説明したユーザー側で用意した辞書型のdataを使ってout_bufをoverwriteする戦略と同じであるため、省略する。<br>
以下は、該当部分のソースコードである。その他の部分は公開したソースコードを確認してほしい。<br>
```c
// 自動で生成した方でout_bufのoverwriteを行う
  stage_name  = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur   = 0;
  stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;
```
### RANDOM HAVOC(ランダムに用意された戦略を選ぶ戦略)<br>
RANDOM HAVOC戦略では、最大で16パターンの戦略をランダムに選択をしてout_bufを変異させていく。<br>
RANDOM HAVOC戦略の前に現在のqueue(queue_cur)にRANDOM HAVOC戦略までの戦略を終わらせたflag(passed_det)を立てる。これにより、次からはRANDOM HAVOC戦略だけから始まるようになる。(詳しくは戦略に入る前処理(dataの点数付け)を参照)<br>
これから、RANDOM HAVOC戦略の説明に入る。<br>
- splice_cycle(SPLICING戦略の部分でflagが立つ)が0の場合次の処理にいく。<br>
  - doing_det(PERFORMANCE SCOREの部分を突破flag)が立っていた場合1024、それ以外の場合は256が選ばれる。これらの値にperf_sore(詳しくは戦略に入る前処理(dataの点数付け)を参照)を100とhavoc_div(平均実行速度が遅いものに大きな値がつく)で割る。それをstage_maxにする。<br>
- splice_cycle(SPLICING戦略の部分でflagが立つ)が0以外の時は次の処理にいく。<br>
  - stage_maxは32 * perf_score / havoc_div / 100になる。<br>
- stage_maxが16より小さい場合は16にする。<br>
- stageループ処理に入る。<br>
  - use_stackingは16パターンある戦略を何回繰り返すかのループ処理の最大値である。この値は2から128までの値がランダムに選択される。<br>
  - use_stackingを最大値にしたループ処理に入る。
    - swtich文で辞書型のdataがあるのであればtrueで2をたして0から16の範囲でランダムに選択される,falseなら0を選んで15を足して0から14の範囲でランダムに選択される<br>
    - 以下のパターンは全てout_bufが挿入される場所、out_bufが書き換わる場所、out_bufに挿入される値、選択されるendianはランダムである。<br>
      0. byte単位でbit反転処理を行う<br>
      1. ランダムに選択された1byteのintresting valueを挿入する戦略<br>
      2. ランダムに選択された2byteのintresting valueをランダムに選択されたendianで挿入する戦略<br>
      3. ランダムに選択された4byteのintresting valueをランダムに選択されたendianで挿入する戦略<br>
      4. ランダムで選ばれたARITH_MAXを1byteのout_bufに減算を行う戦略<br>
      5. ランダムで選ばれたARITH_MAXを1byteのout_bufに加算を行う戦略<br>
      6. ランダムで選ばれたARITH_MAXを2byteのout_bufにランダムに選択されたendianで減算を行う戦略<br>
      7. ランダムで選ばれたARITH_MAXを2byteのout_bufにランダムに選択されたendianで加算を行う戦略<br>
      8. ランダムで選ばれたARITH_MAXを4byteのout_bufにランダムに選択されたendianで減算を行う戦略<br>
      9. ランダムで選ばれたARITH_MAXを4byteのout_bufにランダムに選択されたendianで加算を行う戦略<br>
      10. なんとなく1-255の値を使ってxor戦略<br>
      11. out_bufのデータをdeleteする戦略<br>
      12. 11と同じ<br>
      13. out_bufにout_buf自身を使ってコピーまたはinsert戦略<br>
      14. out_bufにout_buf自身を使って書き換え戦略<br>
      15. extrasを使ってoverwrite戦略<br>
      16. extrasを使ってout_bufに追加する戦略<br>
  - use_stackingループを抜けたら、common_fuzz_stuff関数を実行する<br>
  - out_bufをin_bufを使って元の値に戻す。<br>
  - havoc_queued(初期値はqueued_pathsと同じ)の値と一致しなかった時は次の処理に入る。<br>
    - perf_scoreがhavocの最大スコアである1600以上でなければ、stage_maxとperf_scoreを2倍にする。<br>
    - havoc_queuedにqueued_pathsを代入して値を更新する。<br>
以下に、該当部分のソースコードを載せておく、その他の部分は公開したソースコードを確認してほしい。<br>
```c
  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {//retry_splice(havocの次)の時にflagがたつ

    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  perf_score / havoc_div / 100;//doin_detはパーフォーマンススコアをつけてその後の条件を突破したらつけられる。(基本初めてfuzzingされるもの)
                                               //havoc_divは平均実行速度が遅ければ遅いほど値が大きい

  } else {

    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;

  }

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;//16より小さい時は一番最小の16にサイズを調整する

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));//2から2^7(128)までのランダム値

    stage_cur_val = use_stacking;
 
    for (i = 0; i < use_stacking; i++) {
// extras_cnt + a_extras_cntがあるのであればtrueで2をたして0から16の範囲でランダム化,falseなら0を選んで15を足して0から14の範囲でランダム化
      switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {
//byte単位でbit反転処理を行う
        case 0:

          /* Flip a single bit somewhere. Spooky! */

          FLIP_BIT(out_buf, UR(temp_len << 3));//1byte単位でのbit反転
          break;
//ランダムに選択された1byteのintresting valueを挿入する戦略
        case 1: 

          /* Set byte to interesting value. */

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];//1byte単位のinteresting valueをランダムに入れる
          break;
//ランダムに選択された2byteのintresting valueをランダムに選択されたendianで挿入する戦略
        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;//lenが2byteよりも小さい場合は終了

          if (UR(2)) {//1の場合 little endian

            *(u16*)(out_buf + UR(temp_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];//2byteのinteresting valueをランダムに入れる

          } else {//0の場合 big endian

            *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);//2byteのinteresting valueを入れ替えた値をランダムに入れる

          }

          break;
//ランダムに選択された4byteのintresting valueをランダムに選択されたendianで挿入する戦略
        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          if (UR(2)) {
  
            *(u32*)(out_buf + UR(temp_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }

          break;
//ランダムで選ばれたARITH_MAXを1byteのout_bufに減算を行う戦略
        case 4:

          /* Randomly subtract from byte. */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;
//ランダムで選ばれたARITH_MAXを1byteのout_bufに加算を行う戦略
        case 5:

          /* Randomly add to byte. */

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;
//ランダムで選ばれたARITH_MAXを2byteのout_bufにランダムに選択されたendianで減算を行う戦略
        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

          }

          break;
//ランダムで選ばれたARITH_MAXを2byteのout_bufにランダムに選択されたendianで加算を行う戦略
        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

          }

          break;
//ランダムで選ばれたARITH_MAXを4byteのout_bufにランダムに選択されたendianで減算を行う戦略
        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

          }

          break;
//ランダムで選ばれたARITH_MAXを4byteのout_bufにランダムに選択されたendianで加算を行う戦略
        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

          }

          break;
//なんとなく1-255の値を使ってxor戦略
        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;
//out_bufのデータをdeleteする戦略
        case 11 ... 12: {

            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. */

            u32 del_from, del_len;

            if (temp_len < 2) break;

            /* Don't delete too much. */

            del_len = choose_block_len(temp_len - 1);//deleteできる長さを指定deleteする長さは最小サイズで決める

            del_from = UR(temp_len - del_len + 1);//deketeする先頭をランダムに決める

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);//del_fromからdel_lenの足した場所(deleteされる一番後ろの次)をdel_fromの場所に移動

            temp_len -= del_len;//deleteした長さの減算

            break;

          }
//out_bufにout_buf自身を使ってコピーまたはinsert戦略
        case 13:

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {//1KBを超えていない時

            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u8  actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            if (actually_clone) {// 1,2,3のとき

              clone_len  = choose_block_len(temp_len);//cloneする長さの選定
              clone_from = UR(temp_len - clone_len + 1);//cloneする先頭の選定

            } else {//0のときblock単位でのinsert戦略に強制的になる

              clone_len = choose_block_len(HAVOC_BLK_XL);
              clone_from = 0;

            }

            clone_to   = UR(temp_len);

            new_buf = ck_alloc_nozero(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (actually_clone)
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);//コピー戦略
            else
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);//insert戦略

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);//コピーまたはinsertした次の部分にout_bufのcloneの次の残りの値を入れる

            ck_free(out_buf);
            out_buf = new_buf;//out_bufのポインタをnew_bufにする
            temp_len += clone_len;//cloneした長さ分を加算

          }

          break;
//out_bufにout_buf自身を使って書き換え戦略
        case 14: {

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
               bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) break;

            copy_len  = choose_block_len(temp_len - 1);

            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);

            if (UR(4)) {//75%の確率でout_bufの値を使って書き換える

              if (copy_from != copy_to)
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            } else memset(out_buf + copy_to,
                          UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);//25%の確率でこちらになり、さらに50%の確率で0xffで書き換わる。

            break;

          }

        /* Values 15 and 16 can be selected only if there are any extras
           present in the dictionaries. */
//extrasを使ってoverwrite戦略
        case 15: {

            /* Overwrite bytes with an extra. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {//extrasがないとき、または自動extrasが1とANDをとったとき

              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one. */

              u32 use_extra = UR(a_extras_cnt);
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {//extrasがあった時、または自動extrasが0とANDをとったとき

              /* No auto extras or odds in our favor. Use the dictionary. */

              u32 use_extra = UR(extras_cnt);
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);//insert_atの部分から書き換え

            }

            break;

          }
//extrasを使ってout_bufに追加する戦略
        case 16: {

            u32 use_extra, extra_len, insert_at = UR(temp_len + 1);//out_ufのランダムな長さ
            u8* new_buf;

            /* Insert an extra. Do the same dice-rolling stuff as for the
               previous case. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {//extrasがないとき、または自動extrasが1とANDをとったとき

              use_extra = UR(a_extras_cnt);
              extra_len = a_extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);//out_bufの先頭からinsert_atまでの長さをnew_bufにコピー

              /* Inserted part */
              memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);//後ろにextrasを挿入

            } else {//extrasがあった時、または自動extrasが0とANDをとったとき

              use_extra = UR(extras_cnt);
              extra_len = extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);//後ろにextrasを挿入

            }

            /* Tail */
            memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                   temp_len - insert_at);//out_bufの残りをextrasの後ろにつける

            ck_free(out_buf);
            out_buf   = new_buf;
            temp_len += extra_len;

            break;

          }

      }

    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);//out_bufを元に戻す

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (queued_paths != havoc_queued) {//havoc_queued(初期値はqueued_pathsと同じ)の値と一致しなかった時

      if (perf_score <= HAVOC_MAX_MULT * 100) {//HAVOCの最大スコアよりもperf_scoreが小さい場合
        stage_max  *= 2;//stageを2倍にして長くする
        perf_score *= 2;//スコアを2倍にする
      }

      havoc_queued = queued_paths;//queued_pathsが増えているので数を更新する

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }
```
### SPLICING(dataをspliteする戦略)<br>
- use_spliceingは-M option(force_deterministic flagが立っていない時)以外の時にflagが立っている。<br>
- splice_cycleと比べてspliceingする最大回数である14回より下である。(splice_cycleこのとき加算される)<br>
- queueと現在のqueueの長さが2byte以上でなければならない<br>
- queueの数(queue_paths)が1より多い<br>
この4つの条件に当てはまるとSPLICING戦略に入る<br>
- in_bufとorig_inのaddressが一致しなかった場合現在のin_bufを解放してorig_inと同じアドレスにする。<br>
- 適当にqueueされているtest caseを引っ張ってくる。このとき、現在のtest caseと一致したら同じ処理をもう一度行う。<br>
- splicing_withに適当に引っ張ってきたqueue(tid)を入れる。また、targetに先頭のqueueを入れる。<br>
- tidが100を超えていれば現在のqueueからnext_100をたどっていく。(このときtidは100減算される)次にtidが0になるまでnextをたどっていく。つまり、目的のqueueの場所になるまで辿っていく。
- targetの長さが2byteより下、または現在のqueueであった場合は次のtargetにして、splicing_withを加算する。<br>
- targetがなかった場合は最初からSPLICING戦略をやり直す<br>
- targetのdataをnew_bufにコピーする。<br>
- locate_diffs関数を使って、in_bufとnew_bufを先頭から比べて一番最初に違ったbyte(f_diff)と一番最後に違ったbyte(l_diff)を取得する<br>
- f_diffとl_diffがsplitできるよう長さでなければ最初からSPLICING戦略をやり直す<br>
- splite_atにf_diff + l_diffとf_diffの差分をとった値をランダムに選択された値を代入する<br>
- new_bufの先頭からin_bufの内容をsplite_atの長さまでをコピーする。<br>
- in_bufにnew_bufのアドレスを代入する。<br>
- out_bufのメモリを解放して、targetの長さでallocateしなおして、out_bufにin_buf(実質new_bufの内容)の内容をコピーする。
- RANDOM HAVOC戦略にいく。<br>
以下に、該当部分のソースコードを載せておく、その他の部分は公開したソースコードを確認してほしい。<br>
```c
#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:
//use_spliceingは-M option(force_deterministic flagが立っていない時)以外の時に使われる
//spliceingする最大回数は14回
//queueと現在のqueueの長さが2byte以上でなければならない
  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {//addressが一致しなかった場合現在のin_bufを解放して元に戻す
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */
//適当にqueueされているtest caseを引っ張ってくる。このとき、現在のtest caseと一致したらもう一回
    do { tid = UR(queued_paths); } while (tid == current_entry);

    splicing_with = tid;
    target = queue;
//tidが100を超えていれば現在のqueueからnext_100をたどっていく。次にtidが0になるまでnextをたどっていく。そして目的のtidのqueueにたどり着く
    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */
//targetの長さが2byteより下、または現在のqueueであった場合は次のtargetにしていく
    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;//targetがなかった場合はもう一回最初から

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */
//in_bufとnew_bufの一番最初に違ったbyteと一番最後に違ったbyteを取得する
    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {//splitできるよう長さでなければ
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);//splitの長さを決める

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);//new_bufにsplitした長さ分だけコピー
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);//out_bufにtarget queueの長さの分だけout_bufにコピー

    goto havoc_stage;

  }

#endif /* !IGNORE_FINDS */
```
いかがでしたでしょうか。以上がfuzz_one関数の部分になります。<br>
余裕があったらundocument部分にも触れたかったんですけど、疲れたので今回はこのくらいにしておきます。<br>
次回(もしあればいいなぁ)は、メモリまわり、undocumentの部分、並行処理まわりに触れていきたいと思います。<br>
