// Function: FUN_802920a8
// Entry: 802920a8
// Size: 40 bytes

undefined8 FUN_802920a8(undefined8 param_1,undefined8 param_2)

{
  undefined8 local_18;
  undefined4 local_10;
  
  local_18._0_4_ = (uint)((ulonglong)param_1 >> 0x20);
  local_10 = (uint)((ulonglong)param_2 >> 0x20);
  local_18 = CONCAT44(local_18._0_4_ & 0x7fffffff | local_10 & 0x80000000,(int)param_1);
  return local_18;
}

