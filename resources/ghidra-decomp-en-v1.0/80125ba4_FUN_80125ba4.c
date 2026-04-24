// Function: FUN_80125ba4
// Entry: 80125ba4
// Size: 352 bytes

void FUN_80125ba4(int param_1)

{
  short sVar1;
  ushort uVar2;
  char cVar3;
  
  if (DAT_803dd85a == '\0') {
    if ((param_1 < 0) || (0x14 < param_1)) {
      param_1 = 0x14;
    }
    DAT_803dd85a = '\x01';
    DAT_803dd85b = (undefined)param_1;
    param_1 = param_1 * 0xc;
    if ((*(int *)(&DAT_8031af34 + param_1) != -1) && (cVar3 = FUN_8000cfa0(), cVar3 == '\0')) {
      FUN_8000d200(*(undefined4 *)(&DAT_8031af34 + param_1),FUN_8000d138);
    }
    if (*(char *)(param_1 + -0x7fce50c5) == '\0') {
      sVar1 = *(short *)(param_1 + -0x7fce50c4);
      uVar2 = *(ushort *)(param_1 + -0x7fce50c8);
      if ((uVar2 != 0xffffffff) && (DAT_803dba70 == 0xffff)) {
        FUN_800173c8(0x7c);
        DAT_803dd7a8 = 1;
        DAT_803dd8d0 = 0;
        DAT_803dd8c8 = 0;
        FLOAT_803dd8cc =
             (float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000) - DOUBLE_803e1e78);
        DAT_803dba70 = uVar2;
        DAT_803dd8ca = sVar1;
        FUN_80016c48(&DAT_803a9440);
        DAT_803dd7a9 = 0;
      }
    }
    else {
      (**(code **)(*DAT_803dca68 + 0x38))(*(undefined2 *)(param_1 + -0x7fce50c8),0,0,0);
    }
    DAT_803dd858 = 0x159;
    DAT_803dd856 = 0;
    DAT_803dd854 = 0;
  }
  return;
}

