# Dynamic Dedicated Host Allocation Implementation for CAPA Provider

**Status: IMPLEMENTED ✅**

## Implementation Summary

This implementation adds dynamic dedicated host allocation capabilities to the CAPA provider, enabling automatic provisioning of dedicated hosts for bare metal workloads like OpenShift Virtualization with HyperShift on ROSA HCP, particularly for BYOL Microsoft Windows workloads.

### Key Features Implemented

- **Dynamic Host Allocation**: Automatically allocate dedicated hosts based on instance family requirements
- **Flexible Configuration**: Support for instance family, instance type, quantity, and availability zone specifications
- **Automatic Cleanup**: Optional auto-release of hosts when machines are deleted
- **Resource Tagging**: Support for custom tags on allocated dedicated hosts
- **Validation**: Comprehensive webhook validation for configuration consistency
- **Status Tracking**: Track allocated host IDs in machine status for operational visibility

### Files Modified/Created

- `api/v1beta2/awsmachine_types.go` - Added DynamicHostAllocationSpec and AllocatedHostID fields
- `api/v1beta2/types.go` - Added DedicatedHostInfo struct and dynamic allocation fields
- `api/v1beta2/awsmachine_webhook.go` - Added validation for dynamic allocation configuration
- `pkg/cloud/services/interfaces.go` - Extended EC2Interface with dedicated host management methods
- `pkg/cloud/services/common/common.go` - Added dedicated host API methods to EC2API interface
- `pkg/cloud/services/ec2/dedicatedhosts.go` - New dedicated host service implementation
- `pkg/cloud/services/ec2/instances.go` - Updated instance creation with dynamic allocation logic
- `controllers/awsmachine_controller.go` - Added host cleanup during machine deletion
- `pkg/cloud/services/ec2/dedicatedhosts_test.go` - Comprehensive unit tests
- `examples/machine-with-dynamic-dedicated-host.yaml` - Usage example

## Overview

Based on the analysis of the merged [PR #5548](https://github.com/kubernetes-sigs/cluster-api-provider-aws/pull/5548) and the existing codebase structure, this document outlines a comprehensive plan to add dynamic dedicated host allocation capability to the CAPA provider upstream.

The current implementation in PR #5548 added the ability to specify existing dedicated hosts via `hostID` and `hostAffinity` fields. This plan extends this functionality to **dynamically allocate** dedicated hosts when provisioning bare metal nodes for BYOL Microsoft Windows workloads on OpenShift Virtualization with HyperShift on ROSA HCP.

## Background

The existing dedicated host implementation allows users to specify a pre-allocated dedicated host ID. However, for dynamic environments like OpenShift Virtualization on HyperShift, we need the ability to:

1. Automatically allocate dedicated hosts when needed
2. Place instances on these dynamically allocated hosts
3. Manage the lifecycle of these hosts (allocation and cleanup)
4. Support BYOL licensing requirements for Microsoft Windows workloads

## Implementation Plan

### 1. Create New API Fields for Dynamic Dedicated Host Allocation

**Files to modify:**
- `api/v1beta2/awsmachine_types.go`
- `api/v1beta2/types.go`

**Changes:**
- Add new fields to `AWSMachineSpec`:
  ```go
  // DynamicHostAllocation enables automatic allocation of dedicated hosts
  // +optional
  DynamicHostAllocation *DynamicHostAllocationSpec `json:"dynamicHostAllocation,omitempty"`
  ```

- Add new fields to `AWSMachineStatus`:
  ```go
  // AllocatedHostID tracks the dynamically allocated dedicated host ID
  // +optional
  AllocatedHostID *string `json:"allocatedHostID,omitempty"`
  ```

- Create `DynamicHostAllocationSpec` struct:
  ```go
  // DynamicHostAllocationSpec defines the configuration for dynamic dedicated host allocation
  type DynamicHostAllocationSpec struct {
      // InstanceFamily specifies the EC2 instance family (e.g., "m5", "c5", "r5")
      // +kubebuilder:validation:Required
      InstanceFamily string `json:"instanceFamily"`
      
      // AvailabilityZone specifies the target availability zone for allocation
      // If not specified, uses the same AZ as the instance
      // +optional
      AvailabilityZone *string `json:"availabilityZone,omitempty"`
      
      // InstanceType specifies the specific instance type for the dedicated host
      // If not specified, derives from InstanceFamily
      // +optional
      InstanceType *string `json:"instanceType,omitempty"`
      
      // Quantity specifies the number of dedicated hosts to allocate
      // +kubebuilder:validation:Minimum=1
      // +kubebuilder:validation:Maximum=10
      // +kubebuilder:default=1
      // +optional
      Quantity *int32 `json:"quantity,omitempty"`
      
      // AutoRelease determines whether to automatically release the dedicated host
      // when the machine is deleted
      // +kubebuilder:default=true
      // +optional
      AutoRelease *bool `json:"autoRelease,omitempty"`
      
      // Tags to apply to the allocated dedicated host
      // +optional
      Tags map[string]string `json:"tags,omitempty"`
  }
  ```

- Update `Instance` struct in `types.go` to include dynamic allocation fields

### 2. Add Dedicated Host Management Service Interface

**Files to modify:**
- `pkg/cloud/services/interfaces.go`

**Changes:**
- Extend `EC2Interface` with dedicated host management methods:
  ```go
  // Dedicated Host management
  AllocateDedicatedHost(ctx context.Context, spec *DynamicHostAllocationSpec, availabilityZone string) (string, error)
  ReleaseDedicatedHost(ctx context.Context, hostID string) error
  DescribeDedicatedHost(ctx context.Context, hostID string) (*DedicatedHostInfo, error)
  ListDedicatedHosts(ctx context.Context, filters map[string]string) ([]*DedicatedHostInfo, error)
  ```

**New files to create:**
- `pkg/cloud/services/ec2/dedicatedhosts.go`

**Implementation details:**
- Create `DedicatedHostInfo` struct to encapsulate host details
- Implement AWS EC2 `AllocateHosts`, `ReleaseHosts`, and `DescribeHosts` API calls
- Add proper error handling and logging
- Include cost tracking and billing tag support

### 3. Implement Dynamic Host Allocation Logic in EC2 Service

**Files to modify:**
- `pkg/cloud/services/ec2/instances.go`

**Changes:**
- Modify `CreateInstance` method to handle dynamic allocation:
  ```go
  // Before instance creation, check for dynamic host allocation
  if scope.AWSMachine.Spec.DynamicHostAllocation != nil {
      hostID, err := s.allocateHostIfNeeded(ctx, scope)
      if err != nil {
          return nil, errors.Wrap(err, "failed to allocate dedicated host")
      }
      input.HostID = aws.String(hostID)
      input.HostAffinity = aws.String("host")
      
      // Update machine status with allocated host ID
      scope.AWSMachine.Status.AllocatedHostID = &hostID
  }
  ```

- Add cleanup logic in termination methods:
  ```go
  // In TerminateInstance or DeleteBastion methods
  if scope.AWSMachine.Status.AllocatedHostID != nil && 
     scope.AWSMachine.Spec.DynamicHostAllocation != nil &&
     ptr.Deref(scope.AWSMachine.Spec.DynamicHostAllocation.AutoRelease, true) {
      err := s.ReleaseDedicatedHost(ctx, *scope.AWSMachine.Status.AllocatedHostID)
      if err != nil {
          s.scope.Error(err, "failed to release dedicated host", "hostID", *scope.AWSMachine.Status.AllocatedHostID)
      }
  }
  ```

**New methods to implement:**
- `allocateHostIfNeeded(ctx context.Context, scope *scope.MachineScope) (string, error)`
- `determineInstanceFamily(instanceType string) string`
- `validateHostCompatibility(hostID string, instanceType string) error`

### 4. Add Webhook Validation for Dynamic Allocation Configuration

**Files to modify:**
- `api/v1beta2/awsmachine_webhook.go`

**Changes:**
- Extend `validateHostAffinity()` method:
  ```go
  func (r *AWSMachine) validateHostAffinity() field.ErrorList {
      var allErrs field.ErrorList
      
      // Existing validation for static host allocation
      if r.Spec.HostAffinity != nil {
          if r.Spec.HostID == nil || len(*r.Spec.HostID) == 0 {
              allErrs = append(allErrs, field.Required(field.NewPath("spec.hostID"), "hostID must be set when hostAffinity is configured"))
          }
      }
      
      // New validation for dynamic allocation
      if r.Spec.DynamicHostAllocation != nil {
          // Mutual exclusivity check
          if r.Spec.HostID != nil {
              allErrs = append(allErrs, field.Forbidden(field.NewPath("spec.hostID"), "cannot specify both hostID and dynamicHostAllocation"))
          }
          
          // Validate dynamic allocation spec
          allErrs = append(allErrs, r.validateDynamicHostAllocation()...)
      }
      
      return allErrs
  }
  ```

- Add new validation method:
  ```go
  func (r *AWSMachine) validateDynamicHostAllocation() field.ErrorList {
      var allErrs field.ErrorList
      spec := r.Spec.DynamicHostAllocation
      
      if spec.InstanceFamily == "" {
          allErrs = append(allErrs, field.Required(field.NewPath("spec.dynamicHostAllocation.instanceFamily"), "instanceFamily is required"))
      }
      
      // Validate instance family format
      if !isValidInstanceFamily(spec.InstanceFamily) {
          allErrs = append(allErrs, field.Invalid(field.NewPath("spec.dynamicHostAllocation.instanceFamily"), spec.InstanceFamily, "invalid instance family format"))
      }
      
      // Validate quantity if specified
      if spec.Quantity != nil && (*spec.Quantity < 1 || *spec.Quantity > 10) {
          allErrs = append(allErrs, field.Invalid(field.NewPath("spec.dynamicHostAllocation.quantity"), *spec.Quantity, "quantity must be between 1 and 10"))
      }
      
      return allErrs
  }
  ```

**Files to modify:**
- `api/v1beta2/awsmachinetemplate_webhook.go`

**Changes:**
- Add similar validation for machine templates
- Ensure dynamic allocation configuration is not allowed in certain template contexts

### 5. Create Unit Tests for Dedicated Host Allocation Functionality

**New test files to create:**
- `pkg/cloud/services/ec2/dedicatedhosts_test.go`
- `api/v1beta2/awsmachine_webhook_test.go` (extend existing)

**Test scenarios for dedicated hosts service:**
```go
func TestAllocateDedicatedHost(t *testing.T) {
    tests := []struct {
        name           string
        spec           *DynamicHostAllocationSpec
        availabilityZone string
        expectedError  string
        setupMocks     func(*mocks.MockEC2API)
    }{
        {
            name: "successful allocation",
            spec: &DynamicHostAllocationSpec{
                InstanceFamily: "m5",
                Quantity:       ptr.To(int32(1)),
            },
            availabilityZone: "us-west-2a",
            setupMocks: func(m *mocks.MockEC2API) {
                m.EXPECT().AllocateHosts(gomock.Any(), gomock.Any()).Return(&ec2.AllocateHostsOutput{
                    HostIds: []string{"h-1234567890abcdef0"},
                }, nil)
            },
        },
        // Add more test cases
    }
}
```

**Test scenarios for webhook validation:**
- Valid dynamic allocation configuration
- Mutual exclusivity with static host ID
- Invalid instance family format
- Invalid quantity values
- Required field validation

**Files to extend:**
- `pkg/cloud/services/ec2/instances_test.go`

**Integration test scenarios:**
- Instance creation with dynamic host allocation
- Host allocation failure handling
- Instance termination with host cleanup

### 6. Add E2E Tests for Dynamic Dedicated Host Allocation

**New directories and files to create:**
- `test/e2e/data/infrastructure-aws/withoutclusterclass/kustomize_sources/dedicated-host-dynamic/`
  - `dedicated-host-dynamic-resource-set.yaml`
  - `kustomization.yaml`

**Template example:**
```yaml
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: AWSMachineTemplate
metadata:
  name: "${CLUSTER_NAME}-md-dhd"
spec:
  template:
    spec:
      instanceType: "${AWS_NODE_MACHINE_TYPE}"
      iamInstanceProfile: "nodes.cluster-api-provider-aws.sigs.k8s.io"
      sshKeyName: "${AWS_SSH_KEY_NAME}"
      dynamicHostAllocation:
        instanceFamily: "${INSTANCE_FAMILY}"
        quantity: 1
        autoRelease: true
```

**Files to modify:**
- `test/e2e/suites/unmanaged/unmanaged_functional_test.go`

**E2E test implementation:**
```go
ginkgo.Describe("Dynamic dedicated hosts cluster test", func() {
    ginkgo.It("should create cluster with dynamic dedicated host allocation", func() {
        // Test implementation
        // 1. Create cluster with dynamic allocation
        // 2. Verify host is allocated
        // 3. Verify instance is placed on allocated host
        // 4. Delete cluster
        // 5. Verify host is released (if autoRelease is true)
    })
})
```

**Additional test scenarios:**
- Multiple instances sharing a dynamically allocated host
- Host allocation failure recovery
- Manual host release
- Cost tagging verification

### 7. Update CRDs and Generate Manifest Files

**Commands to run:**
```bash
# Generate CRD manifests
make generate

# Update generated code
make manifests

# Run code generation
make generate-go
```

**Files that will be updated:**
- `config/crd/bases/infrastructure.cluster.x-k8s.io_awsmachines.yaml`
- `config/crd/bases/infrastructure.cluster.x-k8s.io_awsmachinetemplates.yaml`
- `api/v1beta2/zz_generated.deepcopy.go`
- Conversion files in `api/v1beta1/`

### 8. Add Documentation for the New Feature

**New documentation files to create:**
- `docs/book/src/topics/dedicated-hosts-dynamic.md`

**Documentation content:**
- Feature overview and use cases
- Configuration examples
- Cost considerations and billing implications
- Best practices for host allocation
- Troubleshooting guide
- Comparison with static host allocation

**Files to update:**
- `docs/book/src/SUMMARY.md` - Add new documentation to table of contents
- `README.md` - Update feature list if applicable

## Key Design Decisions

### 1. API Design Philosophy
- **Consistency**: Following the existing pattern of optional spec fields with status tracking, similar to how capacity reservations and spot instances are handled
- **Flexibility**: Supporting both static and dynamic allocation modes with clear mutual exclusivity
- **Observability**: Tracking allocated host IDs in status for operational visibility

### 2. Service Architecture
- **Interface Extension**: Extending the existing `EC2Interface` rather than creating a separate service to maintain consistency with current architecture
- **Error Handling**: Implementing robust error handling with proper AWS API error classification
- **Resource Management**: Following AWS tagging best practices for cost tracking and resource management

### 3. Lifecycle Management
- **Allocation Timing**: Allocating hosts during instance creation to ensure availability
- **Cleanup Strategy**: Supporting both automatic and manual cleanup with configurable `autoRelease` option
- **State Tracking**: Maintaining allocation state in machine status for recovery scenarios

### 4. Validation Strategy
- **Early Validation**: Implementing comprehensive webhook validation to catch configuration errors before AWS API calls
- **Mutual Exclusivity**: Ensuring clear separation between static and dynamic allocation modes
- **Resource Limits**: Implementing sensible limits on quantity and other parameters

### 5. Testing Approach
- **Unit Testing**: Comprehensive unit tests with mocked AWS APIs following existing patterns
- **Integration Testing**: E2E tests that validate full allocation/deallocation lifecycle
- **Cost Awareness**: Test infrastructure that properly cleans up allocated hosts to avoid unnecessary costs

## Implementation Sequence

The implementation should follow this specific order:

1. **API Changes First**: Establish the data model and interfaces before implementation
2. **Core Service Implementation**: Build the dedicated host management functionality
3. **Integration with Instance Creation**: Modify existing instance creation flow
4. **Validation Layer**: Add webhook validation to catch configuration errors
5. **Unit Testing**: Ensure individual components work correctly
6. **E2E Testing**: Validate end-to-end functionality
7. **Documentation**: Support user adoption with comprehensive documentation
8. **Code Generation**: Update all generated files and manifests

## Risk Mitigation

### Cost Management
- Implement proper tagging for cost tracking
- Add validation limits on host quantity
- Ensure robust cleanup mechanisms
- Provide clear documentation on cost implications

### Operational Concerns
- Add comprehensive logging for allocation/deallocation events
- Implement proper error handling and recovery
- Provide troubleshooting guidance
- Consider implementing allocation quotas or limits

### Compatibility
- Maintain backward compatibility with existing static allocation
- Ensure proper API versioning and conversion
- Test with existing cluster configurations

## Success Criteria

1. **Functional Requirements**:
   - Dynamic allocation of dedicated hosts based on instance requirements
   - Proper placement of instances on allocated hosts
   - Automatic cleanup of hosts when machines are deleted
   - Support for multiple allocation strategies and configurations

2. **Non-Functional Requirements**:
   - No performance impact on existing instance creation workflows
   - Comprehensive error handling and recovery
   - Clear operational visibility through logs and status
   - Minimal additional complexity for end users

3. **Quality Requirements**:
   - 100% unit test coverage for new functionality
   - Successful E2E test execution
   - Comprehensive webhook validation
   - Complete documentation

This plan leverages the patterns and conventions established in PR #5548 while extending the functionality to support dynamic allocation scenarios required for OpenShift Virtualization workloads. The implementation maintains consistency with existing CAPA patterns and provides a robust foundation for dedicated host management in dynamic cloud environments.