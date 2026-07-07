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
package org.zaproxy.zap.extension.zest;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource;

/** Captures interactable page elements for Zest failure diagnostics. */
final class ZestFailureInteractableCapture {

    private static final Logger LOGGER = LogManager.getLogger(ZestFailureInteractableCapture.class);

    private static final String ELEMENT_SELECTOR_SCRIPT =
            """
function isElementPathUnique(path, documentElement) {
  const elements = documentElement.querySelectorAll(path);
  return elements.length === 1;
}

function isElementXPathUnique(xpath, documentElement) {
  const result = documentElement.evaluate(
    xpath,
    documentElement,
    null,
    XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
    null,
  );
  return result.snapshotLength === 1;
}

function getCSSSelector(element, documentElement) {
  let selector = element.tagName.toLowerCase();
  if (selector === "html") {
    selector = "body";
  } else if (element === documentElement.body) {
    selector = "body";
  } else if (element.parentNode) {
    const parentSelector = getCSSSelector(element.parentNode, documentElement);
    selector = `${parentSelector} > ${selector}`;
  }
  return selector;
}

function getXPath(element, documentElement) {
  if (!element.tagName) {
    return "";
  }

  let selector = element.tagName.toLowerCase();

  if (element.id && isElementXPathUnique(selector, documentElement)) {
    selector += `[@id="${element.id}"]`;
  } else {
    let index = 1;
    let sibling = element.previousSibling;
    let isUnique = true;
    while (sibling) {
      if (
        sibling.nodeType === Node.ELEMENT_NODE &&
        sibling.nodeName === element.nodeName
      ) {
        index += 1;
        isUnique = false;
      }
      sibling = sibling.previousSibling;
    }

    if (isUnique) {
      sibling = element.nextSibling;
      while (sibling) {
        if (
          sibling.nodeType === Node.ELEMENT_NODE &&
          sibling.nodeName === element.nodeName
        ) {
          isUnique = false;
          break;
        }
        sibling = sibling.nextSibling;
      }
    }

    if (index !== 1 || !isUnique) {
      selector += `[${index}]`;
    }
  }

  if (element.parentNode) {
    const parentSelector = getXPath(element.parentNode, documentElement);
    selector = `${parentSelector}/${selector}`;
  }
  return selector;
}

function getSelector(element, documentElement) {
  const selector = { type: "", value: "" };

  if (element.id) {
    selector.type = "css";
    selector.value = `#${element.id}`;
  } else if (
    element.classList.length === 1 &&
    element.classList.item(0) != null &&
    isElementPathUnique(`.${element.classList.item(0)}`, documentElement)
  ) {
    selector.type = "css";
    selector.value = `.${element.classList.item(0)}`;
  } else {
    const cssSelector = getCSSSelector(element, documentElement);
    if (cssSelector && isElementPathUnique(cssSelector, documentElement)) {
      selector.type = "css";
      selector.value = cssSelector;
    } else {
      const xpath = getXPath(element, documentElement);
      if (xpath) {
        selector.type = "xpath";
        selector.value = xpath;
      }
    }
  }

  return selector;
}

return getSelector(arguments[0], document)
""";

    private ZestFailureInteractableCapture() {}

    static List<ScriptDiagnosticSource.WebElement> captureInteractables(WebDriver webDriver) {
        if (!(webDriver instanceof JavascriptExecutor je)) {
            return List.of();
        }
        try {
            List<WebElement> elements =
                    resetWait(
                            webDriver,
                            () -> webDriver.findElements(By.xpath("//input|//button")),
                            List::of);
            List<WebElement> forms =
                    resetWait(
                            webDriver, () -> webDriver.findElements(By.xpath("//form")), List::of);
            List<ScriptDiagnosticSource.WebElement> result = new ArrayList<>(elements.size());
            for (WebElement element : elements) {
                ScriptDiagnosticSource.WebElement diagElement = createElement(je, forms, element);
                if (diagElement != null) {
                    result.add(diagElement);
                }
            }
            return List.copyOf(result);
        } catch (WebDriverException e) {
            LOGGER.debug("Failed to capture interactable elements: {}", e.getMessage());
            return List.of();
        }
    }

    private static ScriptDiagnosticSource.WebElement createElement(
            JavascriptExecutor je, List<WebElement> forms, WebElement element) {
        try {
            Integer formIndex = null;
            WebElement form = (WebElement) je.executeScript("return arguments[0].form", element);
            if (form != null) {
                int idx = forms.indexOf(form);
                formIndex = idx != -1 ? idx : null;
            }

            @SuppressWarnings("unchecked")
            Map<String, String> selectorData =
                    (Map<String, String>) je.executeScript(ELEMENT_SELECTOR_SCRIPT, element);
            String selectorType = selectorData != null ? selectorData.get("type") : null;
            String selectorValue = selectorData != null ? selectorData.get("value") : null;

            return new ScriptDiagnosticSource.WebElement(
                    formIndex,
                    element.getTagName(),
                    element.getAttribute("type"),
                    element.getAttribute("id"),
                    element.getAttribute("name"),
                    element.getAttribute("value"),
                    element.getText(),
                    element.isDisplayed(),
                    element.isEnabled(),
                    selectorType,
                    selectorValue);
        } catch (WebDriverException e) {
            LOGGER.debug("Failed to obtain element data: {}", e.getMessage());
            return null;
        }
    }

    private static <T> T resetWait(WebDriver wd, Supplier<T> function, Supplier<T> defaultValue) {
        Duration duration = wd.manage().timeouts().getImplicitWaitTimeout();
        wd.manage().timeouts().implicitlyWait(Duration.ofMillis(0));
        try {
            return function.get();
        } catch (Exception e) {
            return defaultValue.get();
        } finally {
            wd.manage().timeouts().implicitlyWait(duration);
        }
    }
}
