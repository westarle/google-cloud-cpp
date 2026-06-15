// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "google/cloud/internal/make_jwt_assertion.h"
#include "google/cloud/testing_util/status_matchers.h"
#include "absl/strings/str_split.h"
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>

namespace google {
namespace cloud {
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_BEGIN
namespace internal {
namespace {

using ::google::cloud::testing_util::IsOk;

// This is an invalidated private key. It was created using the Google Cloud
// Platform console, but then the key (and service account) were deleted.
auto constexpr kWellFormattedKey = R"""(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCltiF2oP3KJJ+S
tTc1McylY+TuAi3AdohX7mmqIjd8a3eBYDHs7FlnUrFC4CRijCr0rUqYfg2pmk4a
6TaKbQRAhWDJ7XD931g7EBvCtd8+JQBNWVKnP9ByJUaO0hWVniM50KTsWtyX3up/
fS0W2R8Cyx4yvasE8QHH8gnNGtr94iiORDC7De2BwHi/iU8FxMVJAIyDLNfyk0hN
eheYKfIDBgJV2v6VaCOGWaZyEuD0FJ6wFeLybFBwibrLIBE5Y/StCrZoVZ5LocFP
T4o8kT7bU6yonudSCyNMedYmqHj/iF8B2UN1WrYx8zvoDqZk0nxIglmEYKn/6U7U
gyETGcW9AgMBAAECggEAC231vmkpwA7JG9UYbviVmSW79UecsLzsOAZnbtbn1VLT
Pg7sup7tprD/LXHoyIxK7S/jqINvPU65iuUhgCg3Rhz8+UiBhd0pCH/arlIdiPuD
2xHpX8RIxAq6pGCsoPJ0kwkHSw8UTnxPV8ZCPSRyHV71oQHQgSl/WjNhRi6PQroB
Sqc/pS1m09cTwyKQIopBBVayRzmI2BtBxyhQp9I8t5b7PYkEZDQlbdq0j5Xipoov
9EW0+Zvkh1FGNig8IJ9Wp+SZi3rd7KLpkyKPY7BK/g0nXBkDxn019cET0SdJOHQG
DiHiv4yTRsDCHZhtEbAMKZEpku4WxtQ+JjR31l8ueQKBgQDkO2oC8gi6vQDcx/CX
Z23x2ZUyar6i0BQ8eJFAEN+IiUapEeCVazuxJSt4RjYfwSa/p117jdZGEWD0GxMC
+iAXlc5LlrrWs4MWUc0AHTgXna28/vii3ltcsI0AjWMqaybhBTTNbMFa2/fV2OX2
UimuFyBWbzVc3Zb9KAG4Y7OmJQKBgQC5324IjXPq5oH8UWZTdJPuO2cgRsvKmR/r
9zl4loRjkS7FiOMfzAgUiXfH9XCnvwXMqJpuMw2PEUjUT+OyWjJONEK4qGFJkbN5
3ykc7p5V7iPPc7Zxj4mFvJ1xjkcj+i5LY8Me+gL5mGIrJ2j8hbuv7f+PWIauyjnp
Nx/0GVFRuQKBgGNT4D1L7LSokPmFIpYh811wHliE0Fa3TDdNGZnSPhaD9/aYyy78
LkxYKuT7WY7UVvLN+gdNoVV5NsLGDa4cAV+CWPfYr5PFKGXMT/Wewcy1WOmJ5des
AgMC6zq0TdYmMBN6WpKUpEnQtbmh3eMnuvADLJWxbH3wCkg+4xDGg2bpAoGAYRNk
MGtQQzqoYNNSkfus1xuHPMA8508Z8O9pwKU795R3zQs1NAInpjI1sOVrNPD7Ymwc
W7mmNzZbxycCUL/yzg1VW4P1a6sBBYGbw1SMtWxun4ZbnuvMc2CTCh+43/1l+FHe
Mmt46kq/2rH2jwx5feTbOE6P6PINVNRJh/9BDWECgYEAsCWcH9D3cI/QDeLG1ao7
rE2NcknP8N783edM07Z/zxWsIsXhBPY3gjHVz2LDl+QHgPWhGML62M0ja/6SsJW3
YvLLIc82V7eqcVJTZtaFkuht68qu/Jn1ezbzJMJ4YXDYo1+KFi+2CAGR06QILb+I
lUtj+/nH3HDQjM4ltYfTPUg=
-----END PRIVATE KEY-----
)""";

auto constexpr kPkcs1Key = R"""(-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEApbYhdqD9yiSfkrU3NTHMpWPk7gItwHaIV+5pqiI3fGt3gWAx
7OxZZ1KxQuAkYowq9K1KmH4NqZpOGuk2im0EQIVgye1w/d9YOxAbwrXfPiUATVlS
pz/QciVGjtIVlZ4jOdCk7Frcl97qf30tFtkfAsseMr2rBPEBx/IJzRra/eIojkQw
uw3tgcB4v4lPBcTFSQCMgyzX8pNITXoXmCnyAwYCVdr+lWgjhlmmchLg9BSesBXi
8mxQcIm6yyAROWP0rQq2aFWeS6HBT0+KPJE+21OsqJ7nUgsjTHnWJqh4/4hfAdlD
dVq2MfM76A6mZNJ8SIJZhGCp/+lO1IMhExnFvQIDAQABAoIBAAtt9b5pKcAOyRvV
GG74lZklu/VHnLC87DgGZ27W59VS0z4O7Lqe7aaw/y1x6MiMSu0v46iDbz1OuYrl
IYAoN0Yc/PlIgYXdKQh/2q5SHYj7g9sR6V/ESMQKuqRgrKDydJMJB0sPFE58T1fG
Qj0kch1e9aEB0IEpf1ozYUYuj0K6AUqnP6UtZtPXE8MikCKKQQVWskc5iNgbQcco
UKfSPLeW+z2JBGQ0JW3atI+V4qaKL/RFtPmb5IdRRjYoPCCfVqfkmYt63eyi6ZMi
j2OwSv4NJ1wZA8Z9NfXBE9EnSTh0Bg4h4r+Mk0bAwh2YbRGwDCmRKZLuFsbUPiY0
d9ZfLnkCgYEA5DtqAvIIur0A3Mfwl2dt8dmVMmq+otAUPHiRQBDfiIlGqRHglWs7
sSUreEY2H8Emv6dde43WRhFg9BsTAvogF5XOS5a61rODFlHNAB04F52tvP74ot5b
XLCNAI1jKmsm4QU0zWzBWtv31djl9lIprhcgVm81XN2W/SgBuGOzpiUCgYEAud9u
CI1z6uaB/FFmU3ST7jtnIEbLypkf6/c5eJaEY5EuxYjjH8wIFIl3x/Vwp78FzKia
bjMNjxFI1E/jsloyTjRCuKhhSZGzed8pHO6eVe4jz3O2cY+JhbydcY5HI/ouS2PD
HvoC+ZhiKydo/IW7r+3/j1iGrso56Tcf9BlRUbkCgYBjU+A9S+y0qJD5hSKWIfNd
cB5YhNBWt0w3TRmZ0j4Wg/f2mMsu/C5MWCrk+1mO1FbyzfoHTaFVeTbCxg2uHAFf
glj32K+TxShlzE/1nsHMtVjpieXXrAIDAus6tE3WJjATelqSlKRJ0LW5od3jJ7rw
AyyVsWx98ApIPuMQxoNm6QKBgGETZDBrUEM6qGDTUpH7rNcbhzzAPOdPGfDvacCl
O/eUd80LNTQCJ6YyNbDlazTw+2JsHFu5pjc2W8cnAlC/8s4NVVuD9WurAQWBm8NU
jLVsbp+GW57rzHNgkwofuN/9ZfhR3jJreOpKv9qx9o8MeX3k2zhOj+jyDVTUSYf/
QQ1hAoGBALAlnB/Q93CP0A3ixtWqO6xNjXJJz/De/N3nTNO2f88VrCLF4QT2N4Ix
1c9iw5fkB4D1oRjC+tjNI2v+krCVt2LyyyHPNle3qnFSU2bWhZLobevKrvyZ9Xs2
8yTCeGFw2KNfihYvtggBkdOkCC2/iJVLY/v5x9xw0IzOJbWH0z1I
-----END RSA PRIVATE KEY-----
)""";

TEST(MakeJWTAssertionNoThrow, Basic) {
  auto header = nlohmann::json{
      {"alg", "HS256"}, {"typ", "JWT"}, {"kid", "test-key-name"}};
  auto payload = nlohmann::json{
      {"iss", "--invalid--@developer.gserviceaccount.com"},
      {"sub", "--invalid--@developer.gserviceaccount.com"},
      {"aud", "https//not-a-service.googleapis.com"},
      {"iat", "1511900000"},
      {"exp", "1511903600"},
  };
  auto const assertion =
      MakeJWTAssertionNoThrow(header.dump(), payload.dump(), kWellFormattedKey);
  ASSERT_THAT(assertion, IsOk());

  std::vector<std::string> components = absl::StrSplit(*assertion, '.');
  EXPECT_EQ(components.size(), 3);
}

TEST(MakeJWTAssertionNoThrow, PKCS1) {
  auto header = nlohmann::json{
      {"alg", "HS256"}, {"typ", "JWT"}, {"kid", "test-key-name"}};
  auto payload = nlohmann::json{
      {"iss", "--invalid--@developer.gserviceaccount.com"},
      {"sub", "--invalid--@developer.gserviceaccount.com"},
      {"aud", "https//not-a-service.googleapis.com"},
      {"iat", "1511900000"},
      {"exp", "1511903600"},
  };
  auto const assertion =
      MakeJWTAssertionNoThrow(header.dump(), payload.dump(), kPkcs1Key);
  ASSERT_THAT(assertion, IsOk());

  std::vector<std::string> components = absl::StrSplit(*assertion, '.');
  EXPECT_EQ(components.size(), 3);
}

TEST(MakeJWTAssertionNoThrow, InvalidKey) {
  auto header = nlohmann::json{
      {"alg", "HS256"}, {"typ", "JWT"}, {"kid", "test-key-name"}};
  auto payload = nlohmann::json{
      {"iss", "--invalid--@developer.gserviceaccount.com"},
      {"sub", "--invalid--@developer.gserviceaccount.com"},
      {"aud", "https//not-a-service.googleapis.com"},
      {"iat", "1511900000"},
      {"exp", "1511903600"},
  };
  auto const assertion =
      MakeJWTAssertionNoThrow(header.dump(), payload.dump(), "invalid-key");
  ASSERT_THAT(assertion, Not(IsOk()));
}

}  // namespace
}  // namespace internal
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_END
}  // namespace cloud
}  // namespace google
