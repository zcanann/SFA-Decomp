// Function: FUN_80035920
// Entry: 80035920
// Size: 172 bytes

void FUN_80035920(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,int param_5)

{
  uint uVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar2;
  double in_f2;
  double in_f3;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar3;
  
  uVar3 = FUN_80286840();
  if ((int)uVar3 != 0) {
    *(undefined2 *)(param_3 + 6) = 300;
    uVar2 = extraout_f1;
    uVar1 = FUN_80022f00(param_4);
    *(uint *)(param_3 + 8) = uVar1;
    *(undefined *)(param_3 + 0xae) = 1;
    if ((*(byte *)(param_3 + 0x62) & 0x30) != 0) {
      *(undefined *)(param_3 + 0xaf) = 2;
    }
    FUN_8003586c(uVar2,in_f2,in_f3,in_f4,in_f5,in_f6,in_f7,in_f8,param_5,(int)uVar3,
                 (int)((ulonglong)uVar3 >> 0x20),param_3,0,1,in_r9,in_r10);
  }
  FUN_8028688c();
  return;
}

