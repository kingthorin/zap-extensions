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

import java.io.IOException;
import java.net.HttpCookie;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;

public class CacheController {

    private HttpSender httpSender;
    private HttpMessage base;
    private ParamDiggerConfig config;
    private Cache cache;
    private boolean cachingCheck;
    private HttpMessage bustedMessage;
    private static final String METHOD_NOT_SUPPORTED = "paramdigger.method.not.supported";
    private static final int RANDOM_SEED = 100000;

    private static final Logger logger = LogManager.getLogger(CacheController.class);

    public CacheController(HttpSender httpSender, HttpMessage base, ParamDiggerConfig config) {

        this.httpSender = httpSender;
        this.base = base;
        this.config = config;
        this.cache = new Cache();
    }

    /**
     * Checks if caching happens for a given URL.
     *
     * @param url the URL to check
     * @param method the method to use
     * @return a Cache object which holds the cache state of the site.
     */
    public void checkCaching(String url, Method method) {
        cachingCheck = true;
        /** Fetch default Headers of the site */
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader headers = new HttpRequestHeader();
        switch (method) {
            case GET:
                headers.setMethod(HttpRequestHeader.GET);
                break;
            case POST:
                headers.setMethod(HttpRequestHeader.POST);
                break;
            default:
                break;
        }
        try {
            headers.setURI(new URI(url, true));
            headers.setVersion(HttpHeader.HTTP11);
            msg.setRequestHeader(headers);
            httpSender.sendAndReceive(msg);

            /* Analyze Response Headers */
            HttpResponseHeader responseHeader = msg.getResponseHeader();
            List<HttpHeaderField> responseHeaders = responseHeader.getHeaders();
            for (HttpHeaderField header : responseHeaders) {
                String headerName = header.getName().toLowerCase();
                String headerValue = header.getValue();
                switch (headerName) {
                    case "cache-control":
                    case "pragma":
                        // TODO Add output to Output Panel with header value "%H Header was found
                        // with value %V"
                        break;
                    case "x-cache":
                    case "cf-cache-status":
                    case "x-drupal-cache":
                    case "x-varnish-cache":
                    case "akamai-cache-status":
                    case "server-timing":
                    case "x-iinfo":
                    case "x-nc":
                    case "x-hs-cf-cache-status":
                    case "x-proxy-cache":
                    case "x-cache-hits":
                        // TODO Add output to Output Panel with header value "%H Header was found
                        // with value %V"
                        cache.setIndicator(headerName);
                        break;

                    case "age":
                        /* This is set if Indicator in cache hasn't been set already */
                        // TODO Add output to Output Panel with header value "%H Header was found
                        // with value %V"
                        if (cache.getIndicator() == null || cache.getIndicator().isEmpty()) {
                            cache.setIndicator(headerName);
                        }
                        break;
                    default:
                        break;
                }
            }

            boolean alwaysMiss = false;
            if (cache.getIndicator() == null || cache.getIndicator().isEmpty()) {
                // TODO display some suitable message in OutputPanel that
                // since no x-cache (or other cache hit/miss header) header
                // was found the time will be measured as cache hit/miss indicator.
            } else {
                alwaysMiss = this.checkAlwaysMiss(url, method, cache);
                /* If it's not an always miss, this means we can use a cachebuster */
                if (!alwaysMiss) {
                    /* Check if a query parameter can be used a cache buster. */
                    if (!cache.isCacheBusterFound()) {
                        this.cacheBusterParameter(url, method, cache);
                    }

                    /* Check if a header can be used as a cache buster. */
                    if (!cache.isCacheBusterFound()) {
                        this.cacheBusterHeader(url, method, cache);
                    }

                    /* Check if a  cookmie can be used as a cache buster. */
                    if (!cache.isCacheBusterFound()) {
                        this.cacheBusterCookie(url, method, cache);
                    }

                    /* Check if a HTTP method can be used as a cache buster. */
                    if (!cache.isCacheBusterFound()) {
                        this.cacheBusterHttpMethod(url, method, cache);
                    }
                }
            }
        } catch (Exception e) {
            // TODO Add error message display in output Panel
            logger.error(e, e);
        }
    }

    public boolean isCached(Method method) {
        if (!cachingCheck) {
            this.checkCaching(config.getUrl(), method);
        }
        if ((cache.getIndicator() != null || !cache.getIndicator().isEmpty())
                || cache.hasTimeIndicator()) {
            return true;
        }
        return false;
    }

    public Cache getCache() {
        return cache;
    }

    /**
     * Checks if a HTTP Method can be used as a cache buster.
     *
     * @param url The URL to check.
     * @param method The HTTP Method to check.
     * @param cache The cache object to store the results in.
     * @throws NullPointerException if the URL is null or empty
     * @throws IOException if request was not sent.
     * @throws IllegalArgumentException if the HTTP Method is not supported.
     */
    private void cacheBusterHttpMethod(String url, Method method, Cache cache)
            throws NullPointerException, IOException, IllegalArgumentException {
        String[] httpMethods = {"PURGE", "FASTLYPURGE"};
        for (int i = 0; i < httpMethods.length; i++) {
            HttpRequestHeader headers = new HttpRequestHeader();
            headers.setURI(new URI(url, true));
            headers.setVersion(HttpHeader.HTTP11);
            if (cache.getIndicator() != null && !cache.getIndicator().isEmpty()) {
                /* We make use of the indicator */
                headers.setMethod(httpMethods[i]);
                HttpMessage msg = new HttpMessage();
                msg.setRequestHeader(headers);

                httpSender.sendAndReceive(msg);

                if (msg.getResponseHeader().getStatusCode()
                        == base.getResponseHeader().getStatusCode()) {
                    String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                    if (this.checkCacheHit(indicValue, cache)) {
                        // TODO show output that Method purging didn't work.
                    } else {
                        cache.setCacheBusterFound(true);
                        cache.setCacheBusterIsHttpMethod(true);
                        cache.setCacheBusterName(httpMethods[i]);
                        this.bustedMessage = msg;
                    }
                }
            } else {
                /* Since no indicator was found we try time difference. */
                List<Integer> times = new ArrayList<>();
                HttpMessage msg = new HttpMessage();
                for (int j = 0; j < 4; j++) {
                    if (j % 2 == 0) {
                        headers.setMethod(httpMethods[i]);
                    } else {
                        switch (method) {
                            case GET:
                                headers.setMethod(HttpRequestHeader.GET);
                                break;
                            case POST:
                                headers.setMethod(HttpRequestHeader.POST);
                                break;
                            default:
                                throw new IllegalArgumentException(
                                        Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
                        }
                    }
                    msg.setRequestHeader(headers);

                    httpSender.sendAndReceive(msg);
                    times.add(msg.getTimeElapsedMillis());

                    if (msg.getResponseHeader().getStatusCode()
                            != base.getResponseHeader().getStatusCode()) {
                        // TODO show output that unexpected response code was received
                    }
                }

                boolean skip = false;
                for (int j = 1; j < times.size(); j++) {
                    if ((j % 2 == 1)
                            && (times.get(i - 1) - times.get(i)
                                    < config.getCacheBustingThreshold())) {
                        /* Since the response was faster then usual timing. We can assume it came from a cache. */
                        skip = true;
                        break;
                    }
                }
                if (skip) {
                    continue;
                }
                /* There is a cache and cache buster works! */
                cache.setTimeIndicator(true);
                cache.setCacheBusterFound(true);
                cache.setCacheBusterIsHttpMethod(true);
                cache.setCacheBusterName(httpMethods[i]);
                this.bustedMessage = msg;
            }
        }
    }

    /**
     * Checks if a cookie can be used as a cache buster. Requires users to specify what would be the
     * list of cookies that can be tried as cache busters.
     *
     * @param url The URL to check.
     * @param method The HTTP Method to check.
     * @param cache The cache object to store the results in.
     * @throws NullPointerException if the URL is null or empty
     * @throws IOException if request was not sent.
     * @throws IllegalArgumentException if the HTTP Method is not supported.
     */
    private void cacheBusterCookie(String url, Method method, Cache cache)
            throws NullPointerException, IOException, IllegalArgumentException {
        List<String> cookies = config.getCacheBustingCookies();
        for (int i = 0; i < cookies.size(); i++) {
            HttpRequestHeader headers = new HttpRequestHeader();
            headers.setURI(new URI(url, true));
            headers.setVersion(HttpHeader.HTTP11);
            switch (method) {
                case GET:
                    headers.setMethod(HttpRequestHeader.GET);
                    break;
                case POST:
                    headers.setMethod(HttpRequestHeader.POST);
                    break;
                default:
                    throw new IllegalArgumentException(
                            Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
            }
            if (cache.getIndicator() != null && !cache.getIndicator().isEmpty()) {
                String cb =
                        (Integer.valueOf(new Random(RANDOM_SEED).nextInt() & Integer.MAX_VALUE))
                                .toString();
                HttpCookie cookie = new HttpCookie(cookies.get(i), cb);
                List<HttpCookie> cookieList = new ArrayList<>();
                cookieList.add(cookie);
                headers.setCookies(cookieList);

                HttpMessage msg = new HttpMessage();
                msg.setRequestHeader(headers);
                httpSender.sendAndReceive(msg);

                if (msg.getResponseHeader().getStatusCode()
                        == base.getResponseHeader().getStatusCode()) {
                    String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                    if (this.checkCacheHit(indicValue, cache)) {
                        // TODO show output that Cookie purging didn't work.
                    } else {
                        cache.setCacheBusterFound(true);
                        cache.setCacheBusterIsCookie(true);
                        cache.setCacheBusterName(cookies.get(i));
                        this.bustedMessage = msg;
                    }
                }
            } else {
                /* time has to be considered. */
                List<Integer> times = new ArrayList<>();
                HttpMessage msg = new HttpMessage();
                for (int j = 0; j < 4; j++) {
                    if (j % 2 == 0) {
                        String cb =
                                (Integer.valueOf(
                                                new Random(RANDOM_SEED).nextInt()
                                                        & Integer.MAX_VALUE))
                                        .toString();
                        HttpCookie cookie = new HttpCookie(cookies.get(i), cb);
                        List<HttpCookie> cookieList = new ArrayList<>();
                        cookieList.add(cookie);
                        headers.setCookies(cookieList);
                    }
                    msg.setRequestHeader(headers);
                    httpSender.sendAndReceive(msg);

                    times.add(msg.getTimeElapsedMillis());

                    if (msg.getResponseHeader().getStatusCode()
                            != base.getResponseHeader().getStatusCode()) {
                        // TODO show output that unexpected response code was received
                    }
                }

                boolean skip = false;

                for (int j = 1; j < times.size(); j++) {
                    if ((j % 2 == 1)
                            && (times.get(i - 1) - times.get(i)
                                    < config.getCacheBustingThreshold())) {
                        /* Since the response was faster then usual timing. We can assume it came from a cache. */
                        skip = true;
                        break;
                    }
                }
                if (skip) {
                    continue;
                }

                /* There is a cache and cache buster works! */
                cache.setTimeIndicator(true);
                cache.setCacheBusterFound(true);
                cache.setCacheBusterIsCookie(true);
                cache.setCacheBusterName(cookies.get(i));
                this.bustedMessage = msg;
            }
        }
    }

    /**
     * Checks if a HTTP header can be used as a cache buster.
     *
     * @param url The URL to check.
     * @param method The HTTP Method to check.
     * @param cache The cache object to store the results in.
     * @throws NullPointerException if the URL is null or empty
     * @throws IOException if request was not sent.
     * @throws IllegalArgumentException if the HTTP Method is not supported.
     */
    private void cacheBusterHeader(String url, Method method, Cache cache)
            throws NullPointerException, IOException, IllegalArgumentException {
        String[] headerList = {"Accept-Encoding", "Accept", "Cookie", "Origin"};
        String[] valueList = {"gzip, deflate, ", "*/*, text/", "paramdigger_cookie=", ""};

        for (int i = 0; i < headerList.length; i++) {
            HttpRequestHeader headers = new HttpRequestHeader();
            HttpMessage msg = new HttpMessage();
            switch (method) {
                case GET:
                    headers.setMethod(HttpRequestHeader.GET);
                    break;
                case POST:
                    headers.setMethod(HttpRequestHeader.POST);
                    break;
                default:
                    throw new IllegalArgumentException(
                            Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
            }
            headers.setURI(new URI(url, true));
            headers.setVersion(HttpHeader.HTTP11);

            /* If we have found an indicator then we use it. */
            if (cache.getIndicator() != null && !cache.getIndicator().isEmpty()) {
                String cacheBusterH =
                        valueList[i] + (new Random(RANDOM_SEED).nextInt() & Integer.MAX_VALUE);
                headers.addHeader(headerList[i], cacheBusterH);
                msg.setRequestHeader(headers);

                httpSender.sendAndReceive(msg);

                if (msg.getResponseHeader().getStatusCode()
                        == base.getResponseHeader().getStatusCode()) {
                    String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                    if (this.checkCacheHit(indicValue, cache)) {
                        // TODO show output that headr %H was tried as a cache buster but failed to
                        // work
                    } else {
                        cache.setCacheBusterFound(true);
                        cache.setCacheBusterIsHeader(true);
                        cache.setCacheBusterName(headerList[i]);
                        this.bustedMessage = msg;
                    }
                }
            } else {
                /* Time is our friend */
                List<Integer> timeList = new ArrayList<Integer>();
                /* Setting it to a hardcoded value of 4 so as to reduce the time complexity. */
                for (int j = 0; j < 4; j++) {
                    String cacheBusterH =
                            valueList[i] + (new Random(RANDOM_SEED).nextInt() & Integer.MAX_VALUE);
                    if (headers.getHeader(headerList[i]) == null) {
                        headers.addHeader(headerList[i], cacheBusterH);
                    }
                    headers.setHeader(headerList[i], cacheBusterH);
                    msg.setRequestHeader(headers);

                    httpSender.sendAndReceive(msg);
                    timeList.add(msg.getTimeElapsedMillis());

                    if (msg.getResponseHeader().getStatusCode()
                            != base.getResponseHeader().getStatusCode()) {
                        // TODO show output that unexpected response code was received
                    }
                }

                boolean skip = false;
                for (int j = 1; j < timeList.size(); j++) {
                    if ((j % 2 == 1)
                            && (timeList.get(i - 1) - timeList.get(i)
                                    < config.getCacheBustingThreshold())) {
                        /* Since the response was faster then usual timing. We can assume it came from a cache. */
                        skip = true;
                        break;
                    }
                }
                if (skip) {
                    continue;
                }
                /* There is a cache and cache buster works! */
                cache.setTimeIndicator(true);
                cache.setCacheBusterFound(true);
                cache.setCacheBusterIsHeader(true);
                cache.setCacheBusterName(headerList[i]);
                this.bustedMessage = msg;
            }
        }
    }

    /**
     * Generates a parameter string for a given URL.
     *
     * @param url The input URL to which the cachebuster has to be added
     * @return a URL with a cachebuster parameter having a random value.
     */
    private String generateParameterString(String url) {
        String newUrl;
        if (url.contains("?")) {
            newUrl =
                    url
                            + "&"
                            + config.getCacheBusterName()
                            + "="
                            + (new Random(RANDOM_SEED).nextInt() & Integer.MAX_VALUE);
        } else {
            newUrl =
                    url
                            + "?"
                            + config.getCacheBusterName()
                            + "="
                            + (new Random(RANDOM_SEED).nextInt() & Integer.MAX_VALUE);
        }
        return newUrl;
    }

    /**
     * Checks if a URL parameter can be used as a cache buster. If yes, then the cachebuster is
     * added to the cache object.
     *
     * @param url the URL to be checked.
     * @param method the HTTP method to be used (Refer to Method enum).
     * @param cache the Cache object storing the cache information about the site.
     * @throws NullPointerException if the URL is null or empty
     * @throws IOException if request was not sent.
     * @throws IllegalArgumentException if the HTTP Method is not supported.
     */
    private void cacheBusterParameter(String url, Method method, Cache cache)
            throws NullPointerException, IOException, IllegalArgumentException {
        String newUrl;
        HttpRequestHeader headers = new HttpRequestHeader();
        HttpMessage msg = new HttpMessage();
        switch (method) {
            case GET:
                headers.setMethod(HttpRequestHeader.GET);
                break;
            case POST:
                headers.setMethod(HttpRequestHeader.POST);
                break;
            default:
                throw new IllegalArgumentException(
                        Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
        }

        /* If we have an indicator we use that to deteremine the presence of cache */
        if (cache.getIndicator() != null && !cache.getIndicator().isEmpty()) {
            newUrl = this.generateParameterString(url);
            headers.setURI(new URI(newUrl, true));
            headers.setVersion(HttpHeader.HTTP11);

            msg.setRequestHeader(headers);
            httpSender.sendAndReceive(msg);

            if (msg.getResponseHeader().getStatusCode()
                    == base.getResponseHeader().getStatusCode()) {
                String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                if (this.checkCacheHit(indicValue, cache)) {
                    // TODO show output that identifier defined in config.getCacheBusterName() was
                    // not successfull
                } else {
                    cache.setCacheBusterFound(true);
                    cache.setCacheBusterIsParameter(true);
                    cache.setCacheBusterName(config.getCacheBusterName());
                    this.bustedMessage = msg;
                }
            }
        } else {
            /* This means we don't have any indicator and time is our only friend. */
            List<Integer> times = new ArrayList<>();
            for (int i = 0; i < config.getCacheBustingTimes(); i++) {
                newUrl = this.generateParameterString(url);
                headers.setURI(new URI(newUrl, true));
                headers.setVersion(HttpHeader.HTTP11);

                msg.setRequestHeader(headers);
                httpSender.sendAndReceive(msg);
                times.add(msg.getTimeElapsedMillis());
                if (msg.getResponseHeader().getStatusCode()
                        != base.getResponseHeader().getStatusCode()) {
                    // TODO show unexpected status code error faced during time based cache busting
                }
            }

            for (int i = 1; i < times.size(); i++) {
                if ((i % 2 == 1)
                        && (times.get(i - 1) - times.get(i) < config.getCacheBustingThreshold())) {
                    return;
                }
            }
            cache.setTimeIndicator(true);
            cache.setCacheBusterFound(true);
            cache.setCacheBusterIsParameter(true);
            cache.setCacheBusterName(config.getCacheBusterName());
            this.bustedMessage = msg;
        }
    }

    /**
     * Checks if every requests to the URL is a cache miss or not.
     *
     * @param url the URL to be checked.
     * @param method the HTTP method to be used (Refer to Method enum).
     * @param cache the Cache object storing the cache information about the site.
     * @return true if every request is a cache miss, false otherwise.
     */
    private boolean checkAlwaysMiss(String url, Method method, Cache cache) {
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        switch (method) {
            case GET:
                requestHeader.setMethod(HttpRequestHeader.GET);
                break;
            case POST:
                requestHeader.setMethod(HttpRequestHeader.POST);
                break;
            default:
                throw new IllegalArgumentException(
                        Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
        }
        try {
            requestHeader.setURI(new URI(url, true));
            msg.setRequestHeader(requestHeader);
            httpSender.sendAndReceive(msg);
            if (msg.getResponseHeader().getStatusCode()
                    != base.getResponseHeader().getStatusCode()) {
                // TODO show error on output panel that unexpected status code match error was
                // faced.
            }
            String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
            if (indicValue != null && !this.checkCacheHit(indicValue, cache)) {
                return true;
            }

        } catch (Exception e) {
            return false;
        }
        return false;
    }

    /**
     * Checks if there has been a cache hit or not using a given indicator value.
     *
     * @param indicValue the value of the indicator header.
     * @param cache the Cache object storing the cache information about the site.
     * @return true if there has been a cache hit, false otherwise.
     */
    private boolean checkCacheHit(String indicValue, Cache cache) {
        String indicator = cache.getIndicator();
        if (indicator.equalsIgnoreCase("age")) {
            indicValue = StringUtils.trim(indicValue);
            if (!indicValue.equals("0")) {
                return true;
            }
        }
        if (indicator.equalsIgnoreCase("x-iinfo")) {
            String[] values = StringUtils.split(indicValue, ',');
            if ((values.length > 1) && (values[1].contains("C") || values[1].contains("V"))) {
                return true;
            }
        }
        if (indicator.equalsIgnoreCase("x-cache-hits")) {
            for (String x : StringUtils.split(indicValue, ',')) {
                x = StringUtils.trim(x);
                if (!x.equals("0")) {
                    return true;
                }
            }
        }
        if (indicValue.contains("HIT") || indicValue.contains("hit")) {
            return true;
        }
        return false;
    }

    public HttpMessage getBustedResponse() {
        return this.bustedMessage;
    }
}
