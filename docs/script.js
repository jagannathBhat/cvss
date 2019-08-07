(() => {
    var UI = {
        metrics: {
            AV: { state: 1, value: "" },
            AC: { state: 0, value: "" },
            PR: { state: 0, value: "" },
            UI: { state: 0, value: "" },
            S: { state: 0, value: "" },
            C: { state: 0, value: "" },
            I: { state: 0, value: "" },
            A: { state: 0, value: "" }
        },
        activateMetric: (m) => {
            UI.metrics[m.id].state = 1;
            m.classList.add("--active");
            UI.addNextEvent(m);
            window.scrollTo(0, m.offsetTop + -10);
        },
        addEditEvent: (m) => {
            m.querySelector(".--selected").addEventListener("click", UI.editMetric);
        },
        addNextEvent: (m) => {
            m.querySelectorAll(".metric-value").forEach((e) => {
                e.addEventListener("click", UI.nextMetric);
            });
        },
        collapseMetric: (m) => {
            UI.metrics[m.id].state = -1;
            m.classList.remove("--active");
            m.classList.add("--collapse");
            UI.removeNextEvent(m);
            UI.addEditEvent(m);
        },
        editMetric: (e) => {
            e = e.path[0] ? e.path[0] : e.currentTarget;
            var m = e.parentElement;
            if(document.querySelector(".metric.--active"))
                UI.normalizeMetric(document.querySelector(".metric.--active"));
            m.classList.remove("--collapse");
            UI.activateMetric(e.parentElement);
            UI.removeEditEvent(e.parentElement);
            UI.resetValue(e);
        },
        getChar: (a) => {
            return UI.metrics[a].value;
        },
        nextMetric: (e) => {
            e = e.path[0] ? e.path[0] : e.currentTarget;
            UI.setValue(e);
            UI.collapseMetric(e.parentElement);
            for (var metric in UI.metrics) {
                if(UI.metrics[metric].state === 0) {
                    UI.activateMetric(document.getElementById(metric));
                    return;
                }
            }
            UI.showResult();
        },
        normalizeMetric: (m) => {
            UI.metrics[m.id].state = 0;
            m.classList.remove("--active");
            UI.removeNextEvent(m);
        },
        removeEditEvent: (m) => {
            m.querySelector(".--selected").removeEventListener("click", UI.editMetric);
        },
        removeNextEvent: (m) => {
            m.querySelectorAll(".metric-value").forEach((e) => {
                e.removeEventListener("click", UI.nextMetric);
            });
        },
        reset: () => {
            for (var metric in UI.metrics) {
                UI.metrics[metric].state = 0;
                UI.metrics[metric].value = "";
            }
            document.querySelectorAll(".metric.--active").forEach((e) => {
                UI.removeNextEvent(e);
            });
            document.querySelectorAll(".metric.--collapse").forEach((e) => {
                UI.removeEditEvent(e);
            });
            document.querySelectorAll(".--selected").forEach((e) => {
                e.classList.remove("--selected");
            });
            document.querySelectorAll(".metric").forEach((e) => {
                e.classList.remove("--active");
                e.classList.remove("--collapse");
            });
            window.scrollTo(0, 0);
            document.getElementById("AV").classList.add("--active");
            UI.addNextEvent(document.getElementById("AV"));
            document.querySelector("footer").className = "";
            document.getElementById("score").innerHTML = "";
            document.getElementById("level").innerHTML = "";
        },
        resetValue: (e) => {
            e.classList.remove("--selected");
            UI.metrics[e.parentElement.id].value = "";
        },
        setValue: (e) => {
            e.classList.add("--selected");
            UI.metrics[e.parentElement.id].value = e.innerHTML[0];
        },
        showResult: () => {
            document.querySelector("footer").classList.remove("--" + result.baseSeverity);
            var result = CVSS.calculateCVSSFromMetrics();
            if(result.success) {
                document.querySelector("footer").classList.add("--" + result.baseSeverity);
                document.getElementById("score").innerHTML = result.baseMetricScore;
                document.getElementById("level").innerHTML = result.baseSeverity;
            }
        }
    }

    var CVSS = {
        exploitabilityCoefficient: 8.22,
        scopeCoefficient: 1.08,
        weights: {
            AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
            AC: { H: 0.44, L: 0.77 },
            PR: {
                N: { U: 0.85, C: 0.85 },
                L: { U: 0.62, C: 0.68 },
                H: { U: 0.27, C: 0.5 },
            },
            UI: { N: 0.85, R: 0.62 },
            S: { U: 6.42, C: 7.52 },
            CIA: { N: 0, L: 0.22, H: 0.56 },
        },
        severityRatings: [
            { name: "None", bottom: 0, top: 0 },
            { name: "Low", bottom: 0.1, top: 3.9 },
            { name: "Medium", bottom: 4, top: 6.9 },
            { name: "High", bottom: 7, top: 8.9 },
            { name: "Critical", bottom: 9, top: 10 }
        ],
        calculateCVSSFromMetrics: () => {
            var baseScore;
            var impactSubScore;

            var metricWeightAV = CVSS.weights.AV[UI.getChar("AV")];
            var metricWeightAC = CVSS.weights.AC[UI.getChar("AC")];
            var metricWeightPR = CVSS.weights.PR[UI.getChar("PR")][UI.getChar("S")];
            var metricWeightUI = CVSS.weights.UI[UI.getChar("UI")];
            var metricWeightS = CVSS.weights.S[UI.getChar("S")];
            var metricWeightC = CVSS.weights.CIA[UI.getChar("C")];
            var metricWeightI = CVSS.weights.CIA[UI.getChar("I")];
            var metricWeightA = CVSS.weights.CIA[UI.getChar("A")];

            var exploitabalitySubScore = CVSS.exploitabilityCoefficient * metricWeightAV * metricWeightAC * metricWeightPR * metricWeightUI;
            var impactSubScoreMultiplier = (1 - ((1 - metricWeightC) * (1 - metricWeightI) * (1 - metricWeightA)));

            if (UI.getChar("S") === "U") {
                impactSubScore = metricWeightS * impactSubScoreMultiplier
            } else {
                impactSubScore = metricWeightS * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15)
            }

            if (impactSubScore <= 0) {
                baseScore = 0
            } else {
                if (UI.getChar("S") === "U") {
                    baseScore = CVSS.roundUp1(Math.min((exploitabalitySubScore + impactSubScore), 10))
                } else {
                    baseScore = CVSS.roundUp1(Math.min((exploitabalitySubScore + impactSubScore) * CVSS.scopeCoefficient, 10))
                }
            }

            baseScore = baseScore.toFixed(1);

            return {
                success: true,
                baseMetricScore: baseScore,
                baseSeverity: CVSS.severityRating(baseScore),
            }
        },
        roundUp1: (d) => {
            return Math.ceil(d * 10) / 10
        },
        severityRating: (score) => {
            var severityRatingLength = CVSS.severityRatings.length;
            var validatedScore = Number(score);
            if (isNaN(validatedScore)) {
                return validatedScore
            }
            for (var i = 0; i < severityRatingLength; i++) {
                if (score >= CVSS.severityRatings[i].bottom && score <= CVSS.severityRatings[i].top) {
                    return CVSS.severityRatings[i].name
                }
            }
            return undefined
        }
    };

    window.onload = () => {
        window.scrollTo(0, 0);
        document.getElementById("AV").classList.add("--active");
        UI.addNextEvent(document.getElementById("AV"));
        document.getElementById("reset").addEventListener("click", UI.reset);
    }
})();
