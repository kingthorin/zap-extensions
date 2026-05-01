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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.collections4.Trie;
import org.apache.commons.collections4.trie.PatriciaTrie;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.io.input.BOMInputStream;

// TEMPORARY (JMH forks lack log4j-api on classpath): restore when removing src/jmh benchmark setup.
// import org.apache.logging.log4j.LogManager;
// import org.apache.logging.log4j.Logger;

/**
 * The list of {@link BinRecord}s for credit card numbers.
 *
 * @since 1.0.0
 */
public final class BinList {

    // private static final Logger LOGGER = LogManager.getLogger(BinList.class);
    private static final String BINLIST_FILE = "binlist-data.csv";

    private static BinList singleton;

    private Trie<String, BinRecord> trie;

    private BinList() {
        trie = createTrie();
    }

    public static BinList getSingleton() {
        if (singleton == null) {
            createSingleton();
        }
        return singleton;
    }

    private static synchronized void createSingleton() {
        if (singleton == null) {
            singleton = new BinList();
        }
    }

    /** Package-private for temporary JMH benchmarks in {@code src/jmh}. */
    static List<CSVRecord> loadCsvRecords() {
        try (InputStream in = BinList.class.getResourceAsStream(BINLIST_FILE);
                BOMInputStream bomStream = BOMInputStream.builder().setInputStream(in).get();
                InputStreamReader inStream =
                        new InputStreamReader(bomStream, StandardCharsets.UTF_8)) {

            return CSVFormat.Builder.create()
                    .setHeader()
                    .setSkipHeaderRecord(true)
                    .get()
                    .parse(inStream)
                    .getRecords();
        } catch (NullPointerException | IOException e) {
            // LOGGER.warn("Exception while loading: {}", BINLIST_FILE, e);
            return List.of();
        }
    }

    /** Package-private for temporary JMH benchmarks in {@code src/jmh}. */
    static Trie<String, BinRecord> buildTrieFromRecords(Iterable<CSVRecord> records) {
        Trie<String, BinRecord> trie = new PatriciaTrie<>();
        for (CSVRecord rec : records) {
            trie.put(
                    rec.get("bin"),
                    new BinRecord(
                            rec.get("bin"),
                            rec.get("brand"),
                            rec.get("category"),
                            rec.get("issuer")));
        }
        return trie;
    }

    /** Package-private for temporary JMH benchmarks in {@code src/jmh}. */
    static Map<String, BinRecord> buildHashMapFromRecords(Iterable<CSVRecord> records) {
        Map<String, BinRecord> map = new HashMap<>();
        for (CSVRecord rec : records) {
            map.put(
                    rec.get("bin"),
                    new BinRecord(
                            rec.get("bin"),
                            rec.get("brand"),
                            rec.get("category"),
                            rec.get("issuer")));
        }
        return map;
    }

    private static Trie<String, BinRecord> createTrie() {
        return buildTrieFromRecords(loadCsvRecords());
    }

    /** Same probe order as {@link #get(String)} but for a {@link Map} (exact keys only). */
    static BinRecord lookupLikeGet(Map<String, BinRecord> map, String candidate) {
        BinRecord binRec = map.get(candidate);
        if (binRec == null) {
            binRec = map.get(candidate.substring(0, 6));
        }
        if (binRec == null) {
            binRec = map.get(candidate.substring(0, 8));
        }
        if (binRec == null) {
            binRec = map.get(candidate.substring(0, 5));
        }
        if (binRec == null) {
            binRec = map.get(candidate.substring(0, 7));
        }
        return binRec;
    }

    static BinRecord lookupLikeGet(Trie<String, BinRecord> trie, String candidate) {
        BinRecord binRec = trie.get(candidate);
        if (binRec == null) {
            binRec = trie.get(candidate.substring(0, 6));
        }
        if (binRec == null) {
            binRec = trie.get(candidate.substring(0, 8));
        }
        if (binRec == null) {
            binRec = trie.get(candidate.substring(0, 5));
        }
        if (binRec == null) {
            binRec = trie.get(candidate.substring(0, 7));
        }
        return binRec;
    }

    /**
     * Gets the {@code BinRecord} for the given (candidate) credit card number.
     *
     * @param candidate the candidate credit card number.
     * @return the {@code BinRecord}, or {@code null} if no match found.
     */
    public BinRecord get(String candidate) {
        // Per https://github.com/iannuttall/binlist-data the collection should have BINs 6-8 but
        // based on my searching there are actually entries 5-8. Probe order matches that data.
        return lookupLikeGet(trie, candidate);
    }
}
