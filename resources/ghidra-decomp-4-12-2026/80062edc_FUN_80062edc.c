// Function: FUN_80062edc
// Entry: 80062edc
// Size: 292 bytes

/* WARNING: Removing unreachable block (ram,0x80062fe0) */
/* WARNING: Removing unreachable block (ram,0x80062fd8) */
/* WARNING: Removing unreachable block (ram,0x80062ef4) */
/* WARNING: Removing unreachable block (ram,0x80062eec) */

int FUN_80062edc(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5,
                float *param_6,undefined4 *param_7)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  undefined4 *local_38 [4];
  
  dVar5 = param_2;
  if (param_4 < param_2) {
    dVar5 = param_4;
    param_4 = param_2;
  }
  iVar1 = FUN_80065fcc(param_1,dVar5,param_3,param_5,local_38,0,1);
  *param_6 = (float)dVar5;
  *param_7 = 0;
  iVar3 = 0;
  puVar2 = local_38[0];
  if (0 < iVar1) {
    do {
      if (((*(char *)((float *)*puVar2 + 5) != '\x0e') &&
          (dVar4 = (double)*(float *)*puVar2, dVar5 < dVar4)) && (dVar4 < param_4)) {
        *param_7 = *(undefined4 *)(local_38[0][iVar3] + 0x10);
        *param_6 = *(float *)local_38[0][iVar3];
        return 1 - ((int)((uint)(byte)((*(float *)(local_38[0][iVar3] + 8) < FLOAT_803df930) << 3)
                         << 0x1c) >> 0x1f);
      }
      puVar2 = puVar2 + 1;
      iVar3 = iVar3 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return 0;
}

