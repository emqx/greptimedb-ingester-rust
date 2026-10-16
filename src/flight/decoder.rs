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

use std::pin::Pin;
use std::task::{Context, Poll};

use arrow_flight::decode::{FlightDataDecoder, FlightRecordBatchStream};
use arrow_flight::error::FlightError;
use arrow_flight::FlightData;
use futures_util::{Stream, TryStreamExt};
use tonic::Streaming;

use crate::error::Error;
use crate::Result;

pub struct FlightDecoder {
    stream: FlightRecordBatchStream,
}

impl FlightDecoder {
    pub fn new(stream: Streaming<FlightData>) -> Self {
        let stream = stream.map_err(|status| FlightError::Tonic(Box::new(status)));
        let flight_data_decoder = FlightDataDecoder::new(stream);
        Self {
            stream: FlightRecordBatchStream::new(flight_data_decoder),
        }
    }
}

impl Stream for FlightDecoder {
    type Item = Result<arrow_array::RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream)
            .poll_next(cx)
            .map(|opt| opt.map(|res| res.map_err(Error::from)))
    }
}
