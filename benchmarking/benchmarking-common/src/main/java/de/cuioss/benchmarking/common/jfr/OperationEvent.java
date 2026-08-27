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
package de.cuioss.benchmarking.common.jfr;

import jdk.jfr.*;

/**
 * JFR event for tracking individual benchmark operation performance.
 * This event captures timing and metadata for each operation,
 * enabling analysis of operation variance under concurrent load.
 */
@Name("de.cuioss.benchmark.Operation")
@Label("Benchmark Operation")
@Description("Tracks individual benchmark operation performance")
@Category({"Benchmark", "Performance"})
@StackTrace(false)
public class OperationEvent extends Event {

    @Label("Operation Type")
    @Description("Type of operation being benchmarked")
    public String operationType;

    @Label("Benchmark Name")
    @Description("Name of the benchmark executing this operation")
    public String benchmarkName;

    @Label("Thread Name")
    @Description("Name of the thread executing this operation")
    public String threadName;

    @Label("Payload Size")
    @Description("Size of the operation payload in bytes")
    @DataAmount
    public long payloadSize;

    @Label("Metadata Key")
    @Description("Key for operation metadata")
    public String metadataKey;

    @Label("Metadata Value")
    @Description("Value for operation metadata")
    public String metadataValue;

    @Label("Success")
    @Description("Whether the operation completed successfully")
    public boolean success;

    @Label("Error Type")
    @Description("Type of error if operation failed")
    public String errorType;

    @Label("Concurrent Operations")
    @Description("Number of concurrent operations at the time of execution")
    public int concurrentOperations;
}