# [(${reportTitle})]

## [(#{report.alerts.summary})]

| [(#{report.alerts.summary.risklevel})] | [(#{report.alerts.summary.numalerts})] |
| --- | --- |
[#th:block th:each="i : ${#numbers.sequence(3, 0, -1)}"]| [(${helper.getRiskString(i)})] | [(${alertCounts.get(i)} ?: '0')] |
[/th:block]

## [(#{report.alerts.list})]

| [(#{report.alerts.list.name})] | [(#{report.alerts.list.risklevel})] | [(#{report.alerts.list.numinstances})] |
| --- | --- | --- |
[#th:block th:each="alert: ${alertTree.children}"]| [(${alert.nodeName})] | [(${helper.getRiskString(alert.risk)})] | [(${alert.childCount})] |
[/th:block]

## [(#{report.alerts.detail})]

[#th:block th:each="alert: ${alertTree.children}"]
[#th:block th:if="${alert.userObject.pluginId >= 0}"]
### [ [(${alert.nodeName})] ](https://www.zaproxy.org/docs/alerts/[(${alert.userObject.pluginId})]/)
[/th:block]
[#th:block th:if="${alert.userObject.pluginId < 0}"]
### [(${alert.nodeName})]
[/th:block]

##### [(${helper.getRiskString(alert.risk)})]

### [(#{report.alerts.detail.description})]

[(${alert.userObject.description})]
[#th:block th:each="instance: ${alert.children}"]
* [(#{report.alerts.detail.url})]: [(${instance.userObject.uri})]
  * [(#{report.alerts.detail.method})]: `[(${instance.userObject.method})]`
  * [(#{report.alerts.detail.evidence})]: `[(${instance.userObject.evidence})]`
[/th:block]
[(#{report.alerts.detail.instances})]: [(${alert.childCount})]

### [(#{report.alerts.detail.solution})]

[(${alert.userObject.solution})]

### [(#{report.alerts.detail.reference})]

[#th:block th:each="ref: ${#strings.arraySplit(alert.userObject.reference, '\n')}"]
* [ [(${ref})] ]([(${ref})])
[/th:block]
[#th:block th:if="${alert.userObject.cweId > 0}"]
#### [(#{report.alerts.detail.cweid})]: [ [(${alert.userObject.cweId})] ](https://cwe.mitre.org/data/definitions/[(${alert.userObject.cweId})].html)
[/th:block]
[#th:block th:if="${alert.userObject.wascId > 0}"]
#### [(#{report.alerts.detail.wascid})]: [(${alert.userObject.wascId})]
[/th:block]
[/th:block]
