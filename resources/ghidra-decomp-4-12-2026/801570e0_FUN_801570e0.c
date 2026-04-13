// Function: FUN_801570e0
// Entry: 801570e0
// Size: 168 bytes

void FUN_801570e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  int iVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (*(byte *)(param_10 + 0x33a) == 0) {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
    else if (1 < *(byte *)(param_10 + 0x33a)) {
      *(undefined *)(param_10 + 0x33a) = 0;
    }
    iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
    FUN_8014d504((double)*(float *)(&DAT_8031ff68 + iVar1),param_2,param_3,param_4,param_5,param_6,
                 param_7,param_8,param_9,param_10,(uint)(byte)(&DAT_8031ff70)[iVar1],0,0,in_r8,in_r9
                 ,in_r10);
  }
  FUN_80156dfc(param_9,param_10);
  return;
}

