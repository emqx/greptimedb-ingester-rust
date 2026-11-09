// Copyright 2023 Greptime Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use arrow_flight::error::FlightError;
use greptimedb_ingester::Error;
use tonic::{Code, Status};

#[test]
fn tonic_flight_error_preserves_status() {
    let status = Status::unavailable("transport error");

    let error = Error::from(FlightError::Tonic(status));

    match error {
        Error::Server { status, msg } => {
            assert_eq!(status.code(), Code::Unavailable);
            assert!(msg.contains("transport error"));
        }
        other => panic!("expected server error, got {other:?}"),
    }
}
