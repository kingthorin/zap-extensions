/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramdigger;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.paramdigger.gui.ParamDiggerHistoryTableModel;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

public class CacheControllerUnitTest extends TestUtils {
    private CacheController cacheController;
    private ParamDiggerHistoryTableModel tableModel;
    private HttpSender httpSender =
            new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, 17);
    private ParamDiggerConfig config;

    @BeforeEach
    void init() throws Exception {
        setUpZap();
        startServer();
        config = new ParamDiggerConfig();
    }

    @Test
    void shouldFindCache() throws Exception {
        String path = "/test";
        int count = 0;
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        Response response =
                                newFixedLengthResponse(
                                        Response.Status.OK, NanoHTTPD.MIME_PLAINTEXT, "test");
                        if (count % 2 == 0) {
                            response.addHeader("X-cache", "Miss");
                        } else {
                            response.addHeader("X-cache", "Hit");
                        }

                        return response;
                    }
                });
    }
}
