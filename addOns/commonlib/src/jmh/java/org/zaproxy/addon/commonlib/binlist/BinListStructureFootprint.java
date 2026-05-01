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

import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.collections4.Trie;
import org.apache.commons.csv.CSVRecord;
import org.openjdk.jol.info.GraphLayout;

/**
 * TEMPORARY — run {@code ./gradlew :addOns:commonlib:binListStructureFootprint}. Remove with {@code
 * jmh} source set.
 */
public final class BinListStructureFootprint {

    private BinListStructureFootprint() {}

    public static void main(String[] args) {
        List<CSVRecord> records = BinList.loadCsvRecords();
        System.out.println("rows=" + records.size());
        Trie<String, BinRecord> trie = BinList.buildTrieFromRecords(records);
        Map<String, BinRecord> map = BinList.buildHashMapFromRecords(records);

        GraphLayout glTrie = GraphLayout.parseInstance(trie);
        GraphLayout glMap = GraphLayout.parseInstance(map);

        System.out.println("PatriciaTrie total footprint: " + formatBytesAndMb(glTrie.totalSize()));
        System.out.println(glTrie.toFootprint());
        System.out.println();
        System.out.println("HashMap total footprint: " + formatBytesAndMb(glMap.totalSize()));
        System.out.println(glMap.toFootprint());
    }

    private static String formatBytesAndMb(long bytes) {
        double mib = bytes / (1024.0 * 1024.0);
        return String.format(Locale.ROOT, "%d bytes (%.2f MB)", bytes, mib);
    }
}
