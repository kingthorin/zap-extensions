/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.addon.encoder.processors.predefined;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;
import org.zaproxy.addon.encoder.OutputPanelContext;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;

public class Base64Encoder extends DefaultEncodeDecodeProcessor {

    private static final Base64Encoder INSTANCE = new Base64Encoder();

    @Override
    public EncodeDecodeResult process(String value, OutputPanelContext context) throws Exception {
        String charsetName;
        boolean breakLines;
        if (context != null) {
            charsetName = context.getString(OutputPanelContext.KEY_BASE64_CHARSET);
            breakLines = context.getBoolean(OutputPanelContext.KEY_BASE64_BREAK_LINES);
        } else {
            charsetName = getOptions().getBase64Charset();
            breakLines = getOptions().isBase64DoBreakLines();
        }
        return new EncodeDecodeResult(processInternal(value, charsetName, breakLines));
    }

    @Override
    protected String processInternal(String value) throws IOException {
        return processInternal(
                value, getOptions().getBase64Charset(), getOptions().isBase64DoBreakLines());
    }

    protected String processInternal(String value, String charsetName, boolean breakLines)
            throws IOException {
        return encode(value, charsetName, breakLines);
    }

    private static String encode(String value, String charsetName, boolean breakLines)
            throws IOException {
        Charset charset = Charset.forName(charsetName);
        if (breakLines) {
            return new String(Base64.getMimeEncoder().encode(value.getBytes(charset)), charset);
        }
        return new String(Base64.getEncoder().encode(value.getBytes(charset)), charset);
    }

    public static Base64Encoder getSingleton() {
        return INSTANCE;
    }
}
