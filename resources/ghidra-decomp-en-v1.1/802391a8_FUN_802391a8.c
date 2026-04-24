// Function: FUN_802391a8
// Entry: 802391a8
// Size: 180 bytes

/* WARNING: Removing unreachable block (ram,0x80239234) */
/* WARNING: Removing unreachable block (ram,0x802391b8) */

undefined4
FUN_802391a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,int param_11)

{
  int iVar1;
  double dVar2;
  
  dVar2 = DOUBLE_803e80c0;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar1 = iVar1 + 1) {
    FUN_8009adfc((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(param_11 + iVar1 + 0x81)) - dVar2)
                 ,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,1,1,0,1,0);
  }
  return 0;
}

