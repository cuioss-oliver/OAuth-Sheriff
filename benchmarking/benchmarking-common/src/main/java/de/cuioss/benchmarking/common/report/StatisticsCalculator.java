/*
 * Copyright © 2025-present CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.benchmarking.common.report;

import de.cuioss.benchmarking.common.constants.BenchmarkConstants;
import lombok.Getter;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Provides pure statistical computation utilities for benchmark metrics.
 * <p>
 * This class is responsible for all statistical calculations including:
 * <ul>
 *   <li>Basic statistics (min, max, mean, median)</li>
 *   <li>Moving averages</li>
 *   <li>Percentage changes and trends</li>
 *   <li>Standard deviation and variance</li>
 * </ul>
 * <p>
 * Use this class when you need to perform mathematical/statistical operations on benchmark data.
 * For metric-specific calculations (performance scores, grades), use {@link MetricsComputer}.
 * For time-series analysis and trend detection, use {@link TrendDataProcessor}.
 *
 * @see MetricsComputer for benchmark-specific metric calculations
 * @see TrendDataProcessor for time-series and trend analysis
 */
public final class StatisticsCalculator {

    public static final String COLLECTION_CANNOT_BE_NULL = "Values collection cannot be null";

    private StatisticsCalculator() {
        // Utility class with static methods only
    }

    /**
     * Calculates the arithmetic mean (average) of a collection of values.
     *
     * @param values collection of numeric values
     * @return the mean value, or 0.0 if the collection is empty
     * @throws NullPointerException if values is null
     */
    public static double calculateMean(Collection<Double> values) {
        Objects.requireNonNull(values, COLLECTION_CANNOT_BE_NULL);

        if (values.isEmpty()) {
            return 0.0;
        }

        return values.stream()
                .mapToDouble(Double::doubleValue)
                .average()
                .orElse(0.0);
    }

    /**
     * Finds the minimum value in a collection.
     *
     * @param values collection of numeric values
     * @return the minimum value, or Double.MAX_VALUE if the collection is empty
     * @throws NullPointerException if values is null
     */
    public static double findMin(Collection<Double> values) {
        Objects.requireNonNull(values, COLLECTION_CANNOT_BE_NULL);

        return values.stream()
                .mapToDouble(Double::doubleValue)
                .min()
                .orElse(Double.MAX_VALUE);
    }

    /**
     * Finds the maximum value in a collection.
     *
     * @param values collection of numeric values
     * @return the maximum value, or Double.MIN_VALUE if the collection is empty
     * @throws NullPointerException if values is null
     */
    public static double findMax(Collection<Double> values) {
        Objects.requireNonNull(values, COLLECTION_CANNOT_BE_NULL);

        return values.stream()
                .mapToDouble(Double::doubleValue)
                .max()
                .orElse(Double.MIN_VALUE);
    }

    /**
     * Calculates the median value of a collection.
     *
     * @param values collection of numeric values
     * @return the median value, or 0.0 if the collection is empty
     * @throws NullPointerException if values is null
     */
    public static double calculateMedian(Collection<Double> values) {
        Objects.requireNonNull(values, COLLECTION_CANNOT_BE_NULL);

        if (values.isEmpty()) {
            return 0.0;
        }

        List<Double> sorted = values.stream()
                .sorted()
                .toList();

        int size = sorted.size();
        if (size % 2 == 0) {
            return (sorted.get(size / 2 - 1) + sorted.get(size / 2)) / 2.0;
        } else {
            return sorted.get(size / 2);
        }
    }

    /**
     * Calculates the percentage change between two values.
     * <p>
     * Formula: ((newValue - oldValue) / oldValue) * 100
     *
     * @param oldValue the original value
     * @param newValue the new value
     * @return the percentage change
     */
    public static double calculatePercentageChange(double oldValue, double newValue) {
        if (oldValue == 0) {
            return newValue == 0 ? 0.0 : 100.0;
        }
        return ((newValue - oldValue) / oldValue) * 100;
    }

    /**
     * Calculates a simple moving average for the most recent N values.
     *
     * @param values list of values (assumed to be in chronological order)
     * @param windowSize the number of most recent values to include
     * @return the moving average
     * @throws NullPointerException if values is null
     * @throws IllegalArgumentException if windowSize is less than 1
     */
    public static double calculateMovingAverage(List<Double> values, int windowSize) {
        Objects.requireNonNull(values, "Values list cannot be null");
        if (windowSize < 1) {
            throw new IllegalArgumentException("Window size must be at least 1");
        }

        if (values.isEmpty()) {
            return 0.0;
        }

        int actualWindow = Math.min(windowSize, values.size());
        List<Double> window = values.size() <= actualWindow
                ? values
                : values.subList(values.size() - actualWindow, values.size());

        return calculateMean(window);
    }

    /**
     * Calculates the standard deviation of a collection of values.
     *
     * @param values collection of numeric values
     * @return the standard deviation, or 0.0 if the collection has less than 2 elements
     * @throws NullPointerException if values is null
     */
    /**
     * Calculates a percentile using the nearest-rank method on a pre-sorted list.
     * <p>
     * Definition: index = min(size - 1, floor(size * percentile / 100)) on the
     * ascending-sorted values. This is the single percentile definition used by
     * all benchmarking statistics (transformers and JFR variance analysis).
     *
     * @param sortedAscending values sorted ascending, must not be null
     * @param percentile the percentile to compute (0-100)
     * @return the percentile value, or 0 if the list is empty
     * @throws NullPointerException if sortedAscending is null
     */
    public static double percentile(List<Double> sortedAscending, double percentile) {
        Objects.requireNonNull(sortedAscending, COLLECTION_CANNOT_BE_NULL);
        if (percentile < 0.0 || percentile > 100.0) {
            throw new IllegalArgumentException("Percentile must be between 0 and 100, but was: " + percentile);
        }
        if (sortedAscending.isEmpty()) {
            return 0;
        }
        int index = (int) (sortedAscending.size() * percentile / 100.0);
        if (index >= sortedAscending.size()) {
            index = sortedAscending.size() - 1;
        }
        return sortedAscending.get(index);
    }

    public static double calculateStandardDeviation(Collection<Double> values) {
        Objects.requireNonNull(values, COLLECTION_CANNOT_BE_NULL);

        if (values.size() < 2) {
            return 0.0;
        }

        double mean = calculateMean(values);
        double variance = values.stream()
                .mapToDouble(value -> Math.pow(value - mean, 2))
                .average()
                .orElse(0.0);

        return Math.sqrt(variance);
    }

    /**
     * Calculates an Exponentially Weighted Moving Average (EWMA) baseline from historical values.
     * <p>
     * EWMA gives more weight to recent values while still considering historical context,
     * making it ideal for performance monitoring and trend detection. The decay factor (lambda)
     * determines how quickly older values lose influence.
     * <p>
     * Formula: EWMA = Σ(value_i × λ^i) / Σ(λ^i)
     * where i=0 is the most recent value, i=1 is second most recent, etc.
     *
     * @param values list of historical values, ordered from newest to oldest
     * @param lambda decay factor (typically 0.2-0.3 for performance monitoring).
     *               Smaller values = more weight on recent data.
     * @return the weighted baseline value
     * @throws NullPointerException if values is null
     * @throws IllegalArgumentException if lambda is not in (0, 1] range
     */
    public static double calculateEWMA(List<Double> values, double lambda) {
        Objects.requireNonNull(values, "Values list cannot be null");
        if (lambda <= 0 || lambda > 1) {
            throw new IllegalArgumentException("Lambda must be in range (0, 1], got: " + lambda);
        }

        if (values.isEmpty()) {
            return 0.0;
        }

        if (values.size() == 1) {
            return values.getFirst();
        }

        double weightedSum = 0.0;
        double weightSum = 0.0;
        double currentWeight = 1.0; // Start with weight = λ^0 = 1.0

        for (Double value : values) {
            weightedSum += value * currentWeight;
            weightSum += currentWeight;
            currentWeight *= lambda; // Exponential decay: next weight = current × λ
        }

        return weightedSum / weightSum;
    }

    /**
     * Determines the trend direction based on percentage change and a stability threshold.
     *
     * @param percentageChange the percentage change value
     * @param stabilityThreshold the threshold (as a percentage) below which the trend is considered stable
     * @return "up", "down", or "stable"
     */
    public static String determineTrendDirection(double percentageChange, double stabilityThreshold) {
        if (Math.abs(percentageChange) < stabilityThreshold) {
            return BenchmarkConstants.Report.Badge.TrendDirection.STABLE;
        }
        return percentageChange > 0 ? BenchmarkConstants.Report.Badge.TrendDirection.UP : BenchmarkConstants.Report.Badge.TrendDirection.DOWN;
    }


    /**
     * Statistical summary containing basic statistics for a dataset.
     */
    @Getter
    public static class Statistics {
        private final double min;
        private final double max;
        private final double mean;
        private final double median;
        private final double stdDev;
        private final int count;

        public Statistics(double min, double max, double mean, double median, double stdDev, int count) {
            this.min = min;
            this.max = max;
            this.mean = mean;
            this.median = median;
            this.stdDev = stdDev;
            this.count = count;
        }
    }

    /**
     * Computes comprehensive statistics for a dataset.
     *
     * @param values collection of numeric values
     * @return a Statistics object containing min, max, mean, median, standard deviation, and count
     * @throws NullPointerException if values is null
     */
    public static Statistics computeStatistics(Collection<Double> values) {
        Objects.requireNonNull(values, COLLECTION_CANNOT_BE_NULL);

        return new Statistics(
                findMin(values),
                findMax(values),
                calculateMean(values),
                calculateMedian(values),
                calculateStandardDeviation(values),
                values.size()
        );
    }
}