// Function: FUN_80113634
// Entry: 80113634
// Size: 364 bytes

/* WARNING: Removing unreachable block (ram,0x80113780) */
/* WARNING: Removing unreachable block (ram,0x80113778) */
/* WARNING: Removing unreachable block (ram,0x8011364c) */
/* WARNING: Removing unreachable block (ram,0x80113644) */

void FUN_80113634(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined2 param_5,float *param_6,float *param_7,int *param_8)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  iVar3 = (int)uVar8;
  if (*(char *)(iVar3 + 0x381) != '\0') {
    *(undefined4 *)(iVar3 + 0x318) = 0;
    *(undefined4 *)(iVar3 + 0x31c) = 0;
    *(undefined2 *)(iVar3 + 0x330) = 0;
    fVar1 = FLOAT_803e28ac;
    *(float *)(iVar3 + 0x290) = FLOAT_803e28ac;
    *(float *)(iVar3 + 0x28c) = fVar1;
    *param_8 = 1;
    dVar7 = (double)(*param_6 - *(float *)(iVar2 + 0xc));
    dVar6 = (double)(*param_7 - *(float *)(iVar2 + 0x14));
    dVar4 = FUN_80293900((double)(float)(dVar7 * dVar7 + (double)(float)(dVar6 * dVar6)));
    if ((double)FLOAT_803e28e8 <= dVar4) {
      dVar5 = (double)FLOAT_803e28ec;
      *(float *)(iVar3 + 0x290) = (float)(dVar5 * -(double)(float)(dVar7 / dVar4));
      *(float *)(iVar3 + 0x28c) = (float)(dVar5 * (double)(float)(dVar6 / dVar4));
      *(float *)(iVar2 + 0xc) =
           (float)(dVar4 * (double)(float)(dVar7 / dVar4) + (double)*(float *)(iVar2 + 0xc));
      *(float *)(iVar2 + 0x14) =
           (float)(dVar4 * (double)(float)(dVar6 / dVar4) + (double)*(float *)(iVar2 + 0x14));
      (**(code **)(*DAT_803dd70c + 8))
                ((double)FLOAT_803dc074,(double)FLOAT_803dc074,iVar2,iVar3,param_3,param_4);
    }
    else {
      *param_8 = 0;
    }
    if (*param_8 == 0) {
      *(undefined *)(iVar3 + 0x405) = 0;
      *(undefined2 *)(iVar3 + 0x274) = param_5;
      *(undefined4 *)(iVar3 + 0x2d0) = 0;
      *(undefined *)(iVar3 + 0x25f) = 0;
      FUN_800201ac((int)*(short *)(iVar3 + 0x3f4),0);
    }
  }
  FUN_80286888();
  return;
}

