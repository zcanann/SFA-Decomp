// Function: FUN_801a7e7c
// Entry: 801a7e7c
// Size: 280 bytes

/* WARNING: Removing unreachable block (ram,0x801a7f74) */
/* WARNING: Removing unreachable block (ram,0x801a7f6c) */
/* WARNING: Removing unreachable block (ram,0x801a7e94) */
/* WARNING: Removing unreachable block (ram,0x801a7e8c) */

int FUN_801a7e7c(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5,
                float *param_6,undefined4 *param_7)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  double dVar5;
  undefined4 *local_38 [4];
  
  iVar2 = FUN_80065fcc(param_1,param_2,param_3,param_5,local_38,0,1);
  *param_6 = (float)param_2;
  *param_7 = 0;
  iVar4 = 0;
  iVar1 = iVar2 + -1;
  puVar3 = local_38[0];
  if (0 < iVar2) {
    do {
      if (((*(char *)((float *)*puVar3 + 5) != '\x0e') &&
          (dVar5 = (double)*(float *)*puVar3, param_2 < dVar5)) &&
         ((dVar5 < param_4 || (iVar4 == iVar1)))) {
        *param_7 = *(undefined4 *)(local_38[0][iVar4] + 0x10);
        *param_6 = *(float *)local_38[0][iVar4];
        return 1 - ((int)((uint)(byte)((*(float *)(local_38[0][iVar4] + 8) < FLOAT_803e51e0) << 3)
                         << 0x1c) >> 0x1f);
      }
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  return 0;
}

