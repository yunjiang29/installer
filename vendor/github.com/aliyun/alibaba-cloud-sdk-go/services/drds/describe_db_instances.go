package drds

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

// DescribeDbInstances invokes the drds.DescribeDbInstances API synchronously
func (client *Client) DescribeDbInstances(request *DescribeDbInstancesRequest) (response *DescribeDbInstancesResponse, err error) {
	response = CreateDescribeDbInstancesResponse()
	err = client.DoAction(request, response)
	return
}

// DescribeDbInstancesWithChan invokes the drds.DescribeDbInstances API asynchronously
func (client *Client) DescribeDbInstancesWithChan(request *DescribeDbInstancesRequest) (<-chan *DescribeDbInstancesResponse, <-chan error) {
	responseChan := make(chan *DescribeDbInstancesResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.DescribeDbInstances(request)
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

// DescribeDbInstancesWithCallback invokes the drds.DescribeDbInstances API asynchronously
func (client *Client) DescribeDbInstancesWithCallback(request *DescribeDbInstancesRequest, callback func(response *DescribeDbInstancesResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *DescribeDbInstancesResponse
		var err error
		defer close(result)
		response, err = client.DescribeDbInstances(request)
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

// DescribeDbInstancesRequest is the request struct for api DescribeDbInstances
type DescribeDbInstancesRequest struct {
	*requests.RpcRequest
	DrdsInstanceId string           `position:"Query" name:"DrdsInstanceId"`
	PageNumber     requests.Integer `position:"Query" name:"PageNumber"`
	Search         string           `position:"Query" name:"Search"`
	PageSize       requests.Integer `position:"Query" name:"PageSize"`
	DbInstType     string           `position:"Query" name:"DbInstType"`
}

// DescribeDbInstancesResponse is the response struct for api DescribeDbInstances
type DescribeDbInstancesResponse struct {
	*responses.BaseResponse
	RequestId string                     `json:"RequestId" xml:"RequestId"`
	Items     ItemsInDescribeDbInstances `json:"Items" xml:"Items"`
}

// CreateDescribeDbInstancesRequest creates a request to invoke DescribeDbInstances API
func CreateDescribeDbInstancesRequest() (request *DescribeDbInstancesRequest) {
	request = &DescribeDbInstancesRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Drds", "2019-01-23", "DescribeDbInstances", "drds", "openAPI")
	request.Method = requests.POST
	return
}

// CreateDescribeDbInstancesResponse creates a response to parse from DescribeDbInstances response
func CreateDescribeDbInstancesResponse() (response *DescribeDbInstancesResponse) {
	response = &DescribeDbInstancesResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}