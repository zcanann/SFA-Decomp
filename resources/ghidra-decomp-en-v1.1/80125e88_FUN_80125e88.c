// Function: FUN_80125e88
// Entry: 80125e88
// Size: 352 bytes

void FUN_80125e88(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  short sVar1;
  ushort uVar2;
  char cVar3;
  int iVar4;
  undefined8 extraout_f1;
  
  if (DAT_803de4da == '\0') {
    if ((param_9 < 0) || (0x14 < param_9)) {
      param_9 = 0x14;
    }
    DAT_803de4da = '\x01';
    DAT_803de4db = (undefined)param_9;
    iVar4 = param_9 * 0xc;
    if ((*(int *)(&DAT_8031bb84 + iVar4) != -1) && (cVar3 = FUN_8000cfc0(), cVar3 == '\0')) {
      FUN_8000d220(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    if (*(char *)(iVar4 + -0x7fce4475) == '\0') {
      sVar1 = *(short *)(iVar4 + -0x7fce4474);
      uVar2 = *(ushort *)(iVar4 + -0x7fce4478);
      if ((uVar2 != 0xffffffff) && (DAT_803dc6d8 == 0xffff)) {
        FUN_80017400(0x7c);
        DAT_803de428 = 1;
        DAT_803de550 = 0;
        DAT_803de548 = 0;
        FLOAT_803de54c =
             (float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000) - DOUBLE_803e2af8);
        DAT_803dc6d8 = uVar2;
        DAT_803de54a = sVar1;
        FUN_80016c80((undefined4 *)&DAT_803aa0a0);
        DAT_803de429 = 0;
      }
    }
    else {
      (**(code **)(*DAT_803dd6e8 + 0x38))(*(undefined2 *)(iVar4 + -0x7fce4478),0,0,0);
    }
    DAT_803de4d8 = 0x159;
    DAT_803de4d6 = 0;
    DAT_803de4d4 = 0;
  }
  return;
}

