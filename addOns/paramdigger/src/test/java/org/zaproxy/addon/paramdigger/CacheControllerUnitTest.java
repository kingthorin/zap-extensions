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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

public class CacheControllerUnitTest extends TestUtils {
    private CacheController cacheController;
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
    void shouldFindCacheWithParameterCacheBuster() throws Exception {
        String path = "/test";
        Map<String, String> params = new HashMap<>();
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    int count = 0;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        Map<String, List<String>> ps = session.getParameters();
                        String header = "x-cache";
                        String value = "";
                        for (Map.Entry<String, List<String>> entry : ps.entrySet()) {
                            if (!params.containsKey(entry.getKey())) {
                                params.put(entry.getKey(), entry.getValue().get(0));
                                value = "miss";
                            } else if (params.get(entry.getKey()).equals(entry.getValue().get(0))) {
                                value = "hit";
                            } else {
                                value = "miss";
                            }
                        }
                        if (value.isEmpty() && count == 0) {
                            value = "miss";
                            count++;
                        } else if (value.isEmpty() && count > 0) {
                            value = "hit";
                        }
                        Response response =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeName.html",
                                                new String[][] {{"q", ""}, {"p", ""}}));
                        response.addHeader(header, value);
                        return response;
                    }
                });
        String url = this.getHttpMessage(path).getRequestHeader().getURI().toString();
        config.setUrl(url);
        cacheController = new CacheController(this.httpSender, config);

        assertThat(cacheController.isCached(Method.GET), equalTo(true));
        assertThat(cacheController.getCache().getIndicator(), equalTo("x-cache"));
        assertThat(cacheController.getCache().isCacheBusterFound(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterIsParameter(), equalTo(true));
    }
}
