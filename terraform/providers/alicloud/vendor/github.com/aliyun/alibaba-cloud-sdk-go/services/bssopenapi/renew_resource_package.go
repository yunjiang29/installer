package bssopenapi

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
)

// RenewResourcePackage invokes the bssopenapi.RenewResourcePackage API synchronously
func (client *Client) RenewResourcePackage(request *RenewResourcePackageRequest) (response *RenewResourcePackageResponse, err error) {
	response = CreateRenewResourcePackageResponse()
	err = client.DoAction(request, response)
	return
}

// RenewResourcePackageWithChan invokes the bssopenapi.RenewResourcePackage API asynchronously
func (client *Client) RenewResourcePackageWithChan(request *RenewResourcePackageRequest) (<-chan *RenewResourcePackageResponse, <-chan error) {
	responseChan := make(chan *RenewResourcePackageResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.RenewResourcePackage(request)
		if err != nil {
			errChan <- err
		} else {
			responseChan <- response
		}
	})
	if err != nil {
		errChan <- err
		close(responseChan)
		close(errChan)
	}
	return responseChan, errChan
}

// RenewResourcePackageWithCallback invokes the bssopenapi.RenewResourcePackage API asynchronously
func (client *Client) RenewResourcePackageWithCallback(request *RenewResourcePackageRequest, callback func(response *RenewResourcePackageResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *RenewResourcePackageResponse
		var err error
		defer close(result)
		response, err = client.RenewResourcePackage(request)
		callback(response, err)
		result <- 1
	})
	if err != nil {
		defer close(result)
		callback(nil, err)
		result <- 0
	}
	return result
}

// RenewResourcePackageRequest is the request struct for api RenewResourcePackage
type RenewResourcePackageRequest struct {
	*requests.RpcRequest
	OwnerId       requests.Integer `position:"Query" name:"OwnerId"`
	EffectiveDate string           `position:"Query" name:"EffectiveDate"`
	Duration      requests.Integer `position:"Query" name:"Duration"`
	InstanceId    string           `position:"Query" name:"InstanceId"`
	PricingCycle  string           `position:"Query" name:"PricingCycle"`
}

// RenewResourcePackageResponse is the response struct for api RenewResourcePackage
type RenewResourcePackageResponse struct {
	*responses.BaseResponse
	RequestId string                     `json:"RequestId" xml:"RequestId"`
	OrderId   int64                      `json:"OrderId" xml:"OrderId"`
	Success   bool                       `json:"Success" xml:"Success"`
	Code      string                     `json:"Code" xml:"Code"`
	Message   string                     `json:"Message" xml:"Message"`
	Data      DataInRenewResourcePackage `json:"Data" xml:"Data"`
}

// CreateRenewResourcePackageRequest creates a request to invoke RenewResourcePackage API
func CreateRenewResourcePackageRequest() (request *RenewResourcePackageRequest) {
	request = &RenewResourcePackageRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("BssOpenApi", "2017-12-14", "RenewResourcePackage", "", "")
	request.Method = requests.POST
	return
}

// CreateRenewResourcePackageResponse creates a response to parse from RenewResourcePackage response
func CreateRenewResourcePackageResponse() (response *RenewResourcePackageResponse) {
	response = &RenewResourcePackageResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}