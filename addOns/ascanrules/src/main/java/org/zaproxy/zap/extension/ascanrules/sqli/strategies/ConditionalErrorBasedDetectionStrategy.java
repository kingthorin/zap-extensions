/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures.Dbms;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects conditional-error blind SQL injection: a payload whose database error appears only when
 * an injected condition is true, and is absent when it is false. Reaches boolean-only / blind
 * shapes the plain error strategy cannot (WAVSEP's {@code WithDifferent200Responses} and
 * silent-error pages) without any time delay -- the signal is error presence across a probe pair,
 * not elapsed time, so this stays a non-timing technique.
 *
 * <p>For each {@link ConditionalErrorPayloads.Condition} it sends the AND_FALSE probe first (which
 * must answer with no database error), then the AND_TRUE probe of the identical shape (which must
 * raise one). Alert iff FALSE is clean AND TRUE errors, the baseline is clean, and a benign control
 * value does not already error ({@link StrictInputValidationGuard}) -- so a page that errors on any
 * metacharacter (input validation / honeypot) fails closed, because its FALSE probe errors too.
 *
 * <p>The error test reuses {@link DbErrorSignatures} for a specific engine message, and falls back
 * to a database-mentioning server error the way {@link ErrorBasedDetectionStrategy} does, so a
 * custom "SQL query failed" page still counts while a bare input-validation 500 does not.
 */
public class ConditionalErrorBasedDetectionStrategy implements DetectionStrategy {

    /**
     * Case-insensitive markers of database content in an error page. Looser than {@link
     * DbErrorSignatures} on purpose, matching {@link ErrorBasedDetectionStrategy}: a custom error
     * page that mentions the database without quoting an engine message must still count. The
     * divide-by-zero markers catch a bare arithmetic error page from the {@code 1/0} branch that
     * carries no engine name.
     */
    private static final List<String> DB_ERROR_MENTIONS =
            List.of(
                    "sql",
                    "jdbc",
                    "odbc",
                    "sqlite",
                    "mysql",
                    "mariadb",
                    "postgres",
                    "pgsql",
                    "oracle",
                    "db2",
                    "division by zero",
                    "divide by zero");

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue = context.getOriginalValue() == null ? "" : context.getOriginalValue();
        int budget = context.getRemainingBudget();
        // Need at least one false/true pair (the baseline is already fetched); skip entirely
        // (sends nothing) so a strength with budget 0 costs no requests.
        if (budget < 2) {
            return false;
        }

        HttpMessage baseline = context.getCachedBaseline();
        // Early exit: a page that already errors on the baseline, or on a value with no SQL
        // metacharacters at all, errors on anything, so a conditional error says nothing about the
        // payload (the WAVSEP prepared-statement / input-validation trap).
        if (hasDbError(baseline) || StrictInputValidationGuard.errorsOnBenignInput(context)) {
            return false;
        }

        int used = 0;
        for (ConditionalErrorPayloads.Condition condition : ConditionalErrorPayloads.CONDITIONS) {
            if (context.isStopped() || used + 2 > budget) {
                return false;
            }

            // FALSE probe first: it must answer with no database error. If it errors, the page
            // errors on this shape regardless of the condition, so the pair is not a discriminator.
            String falseValue = originalValue + condition.andFalse();
            HttpMessage falseMsg = context.newMessage();
            context.setParam(falseMsg, falseValue);
            context.sendAndReceive(falseMsg);
            used++;
            if (hasDbError(falseMsg)) {
                continue;
            }

            if (context.isStopped() || used + 1 > budget) {
                return false;
            }

            // TRUE probe, identical shape: it must raise a database error the FALSE probe did not.
            String trueValue = originalValue + condition.andTrue();
            HttpMessage trueMsg = context.newMessage();
            context.setParam(trueMsg, trueValue);
            context.sendAndReceive(trueMsg);
            used++;

            Optional<Dbms> dbms = DbErrorSignatures.identify(trueMsg.getResponseBody().toString());
            if (dbms.isPresent() || isDbServerError(trueMsg)) {
                raise(context, dbms, trueMsg, falseValue, trueValue);
                return true;
            }
        }
        return false;
    }

    private static void raise(
            ScanContext context,
            Optional<Dbms> dbms,
            HttpMessage trueMsg,
            String falseValue,
            String trueValue) {
        String evidence =
                dbms.flatMap(d -> d.findMatchedFragment(trueMsg.getResponseBody().toString()))
                        .orElse(trueMsg.getResponseHeader().getPrimeHeader().trim());
        context.newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(context.getParamName())
                .setAttack(trueValue)
                .setEvidence(evidence)
                .setOtherInfo(
                        "Database error raised only when the injected condition is true: ["
                                + falseValue
                                + "] clean, ["
                                + trueValue
                                + "] errors"
                                + dbms.map(d -> " (Likely RDBMS: " + d.getLabel() + ")").orElse(""))
                .setMessage(trueMsg)
                .raise();
    }

    /** Whether the response carries a known DB error signature or a database-mentioning 5xx. */
    private static boolean hasDbError(HttpMessage msg) {
        return DbErrorSignatures.identify(msg.getResponseBody().toString()).isPresent()
                || isDbServerError(msg);
    }

    private static boolean isDbServerError(HttpMessage msg) {
        int status = msg.getResponseHeader().getStatusCode();
        if (status < 500 || status >= 600) {
            return false;
        }
        String body = msg.getResponseBody().toString().toLowerCase(Locale.ROOT);
        return DB_ERROR_MENTIONS.stream().anyMatch(body::contains);
    }
}
