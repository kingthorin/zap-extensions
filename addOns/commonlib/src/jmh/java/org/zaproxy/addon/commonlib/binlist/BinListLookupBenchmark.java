/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.commonlib.binlist;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;
import java.util.concurrent.TimeUnit;
import org.apache.commons.csv.CSVRecord;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

/**
 * TEMPORARY — remove with {@code jmh} source set. PatriciaTrie (via {@link BinList#get(String)}) vs
 * {@link java.util.HashMap} with the same probe sequence.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Fork(2)
@Warmup(iterations = 2, time = 2, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 2, timeUnit = TimeUnit.SECONDS)
public class BinListLookupBenchmark {

    static final int CANDIDATE_POOL = 4096;

    @State(Scope.Benchmark)
    public static class SharedState {
        String[] candidates;
        BinList binList;
        Map<String, BinRecord> map;

        @Setup
        public void setup() {
            List<CSVRecord> records = BinList.loadCsvRecords();
            if (records.isEmpty()) {
                throw new IllegalStateException("binlist-data.csv missing or empty on classpath");
            }
            List<String> bins = new ArrayList<>(records.size());
            for (CSVRecord r : records) {
                bins.add(r.get("bin"));
            }
            SplittableRandom rnd = new SplittableRandom(0xB1B105E5L);
            int n = bins.size();
            candidates = new String[CANDIDATE_POOL];
            for (int i = 0; i < CANDIDATE_POOL; i++) {
                candidates[i] = bins.get(rnd.nextInt(n)) + "1234567890";
            }
            map = BinList.buildHashMapFromRecords(records);
            binList = BinList.getSingleton();
        }
    }

    @State(Scope.Thread)
    public static class ThreadState {
        int idx;
    }

    @Benchmark
    public void lookupPatriciaTrie(SharedState shared, ThreadState ts, Blackhole bh) {
        String c = shared.candidates[ts.idx++ & (CANDIDATE_POOL - 1)];
        bh.consume(shared.binList.get(c));
    }

    @Benchmark
    public void lookupHashMap(SharedState shared, ThreadState ts, Blackhole bh) {
        String c = shared.candidates[ts.idx++ & (CANDIDATE_POOL - 1)];
        bh.consume(BinList.lookupLikeGet(shared.map, c));
    }
}
