"""Reviewed EKS management boundary, not authority to operate either cluster."""

SHARED_PROTECTION_POLICY = "eks-shared-crossplane-objects-only-v1"
EXISTING_WORKLOAD_BOUNDARY = {
    "managementClusterRole": "Crossplane control plane only",
    "existingKindWorkloadsOwner": "external to the EKS environment",
    "migrationAllowed": False,
    "adoptionAllowed": False,
    "replicaOrScheduleWritesAllowed": False,
    "historicalWorkloadStateIsPrecondition": False,
    "workloadInventoryQueriesAllowed": False,
    "sharedControllerProtection": SHARED_PROTECTION_POLICY,
}
