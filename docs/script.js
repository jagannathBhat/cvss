(() => {
    var UI = {
        metricNo: 0,
        addEvent: () => {
            document.querySelectorAll(".metric.--active .metric-value").forEach((e) => {
                e.addEventListener("click", UI.nextMetric);
            });
        },
        nextMetric: (e) => {
            e = e.path[0];
            document.querySelectorAll(".metric.--active .metric-value").forEach((e) => {
                e.removeEventListener("click", UI.nextMetric);
            });
            e.classList.add("--selected");
            if (UI.metricNo < document.querySelectorAll(".metric").length) {
                document.querySelector(".metric.--active").classList.add("--collapse");
                document.querySelector(".metric.--active").classList.remove("--active");
            }
            if (UI.metricNo < document.querySelectorAll(".metric").length - 1) {
                document.querySelectorAll(".metric")[++UI.metricNo].classList.add("--active");
                window.scrollTo(0, document.querySelector(".metric.--active").offsetTop + -10);
                UI.addEvent(e);
            } else if (UI.metricNo === document.querySelectorAll(".metric").length - 1) {
                var result = CVSS.calculateCVSSFromMetrics();
                if (result.success === true) {
                    document.getElementById("score").innerHTML = result.baseMetricScore;
                    document.getElementById("level").innerHTML = result.baseSeverity;
                    document.querySelector("footer").classList.add("--" + result.baseSeverity);
                } else {
                    document.getElementById("score").innerHTML = "0.0";
                    document.getElementById("level").innerHTML = "None";
                    document.querySelector("footer").classList.add("--None");
                }
            }
        },
        reset: () => {
            UI.metricNo = 0;
            document.querySelectorAll(".metric.--collapse").forEach((e) => {
                e.classList.remove("--collapse");
            });
            document.querySelectorAll(".metric-value.--selected").forEach((e) => {
                e.classList.remove("--selected");
            });
            document.querySelectorAll(".metric")[UI.metricNo].classList.add("--active");
            window.scrollTo(0, 0);
            document.querySelector("footer").className = "";
            UI.addEvent();
        }
    }

    var CVSS = {
        exploitabilityCoefficient: 8.22,
        scopeCoefficient: 1.08,
        Weight: {
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

            var metricWeightAV = CVSS.Weight.AV[CVSS.getChar("AV")];
            var metricWeightAC = CVSS.Weight.AC[CVSS.getChar("AC")];
            var metricWeightPR = CVSS.Weight.PR[CVSS.getChar("PR")][CVSS.getChar("S")];
            var metricWeightUI = CVSS.Weight.UI[CVSS.getChar("UI")];
            var metricWeightS = CVSS.Weight.S[CVSS.getChar("S")];
            var metricWeightC = CVSS.Weight.CIA[CVSS.getChar("C")];
            var metricWeightI = CVSS.Weight.CIA[CVSS.getChar("I")];
            var metricWeightA = CVSS.Weight.CIA[CVSS.getChar("A")];

            var exploitabalitySubScore = CVSS.exploitabilityCoefficient * metricWeightAV * metricWeightAC * metricWeightPR * metricWeightUI;
            var impactSubScoreMultiplier = (1 - ((1 - metricWeightC) * (1 - metricWeightI) * (1 - metricWeightA)));

            if (CVSS.getChar("S") === "U") {
                impactSubScore = metricWeightS * impactSubScoreMultiplier
            } else {
                impactSubScore = metricWeightS * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15)
            }

            if (impactSubScore <= 0) {
                baseScore = 0
            } else {
                if (CVSS.getChar("S") === "U") {
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
        getChar: (a) => {
            return document.querySelector("#" + a + " .--selected").innerHTML[0]
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
        UI.addEvent();
        document.getElementById("reset").addEventListener("click", UI.reset);
    }
})();