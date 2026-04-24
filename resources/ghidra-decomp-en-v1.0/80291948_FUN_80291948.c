// Function: FUN_80291948
// Entry: 80291948
// Size: 40 bytes

/* WARNING: Could not reconcile some variable overlaps */

ulonglong FUN_80291948(ulonglong param_1,undefined8 param_2)

{
  ulonglong local_18;
  uint local_10;
  
  local_18._0_4_ = (uint)(param_1 >> 0x20);
  local_10 = (uint)((ulonglong)param_2 >> 0x20);
  local_18 = param_1 & 0xffffffff |
             (ulonglong)(local_18._0_4_ & 0x7fffffff | local_10 & 0x80000000) << 0x20;
  return local_18;
}

