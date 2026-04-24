// Function: FUN_801d1cdc
// Entry: 801d1cdc
// Size: 652 bytes

/* WARNING: Removing unreachable block (ram,0x801d1f48) */
/* WARNING: Removing unreachable block (ram,0x801d1cec) */

void FUN_801d1cdc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  ushort *puVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  float *pfVar5;
  int in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar6;
  float *pfVar7;
  double dVar8;
  double dVar9;
  double in_f31;
  double in_ps31_1;
  uint local_38;
  int local_34 [11];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar1 = (ushort *)FUN_80286840();
  pfVar7 = *(float **)(puVar1 + 0x5c);
  iVar6 = *(int *)(puVar1 + 0x26);
  iVar2 = FUN_8002bac4();
  iVar3 = FUN_8002ba84();
  bVar4 = FUN_8002b11c((int)puVar1);
  if (bVar4 == 0) {
    if (*(char *)((int)pfVar7 + 0x136) == '\b') {
      while (iVar2 = FUN_800375e4((int)puVar1,&local_38,(uint *)0x0,(uint *)0x0), iVar2 != 0) {
        if (local_38 == 0x7000b) {
          puVar1[3] = puVar1[3] | 0x4000;
          FUN_80035ff8((int)puVar1);
          FUN_80020000((int)*(short *)(pfVar7 + 0x4d));
          FUN_800201ac(0x12e,0);
          if (puVar1[0x23] == 0x658) {
            FUN_80099c40((double)FLOAT_803e5f40,puVar1,0xff,0x28);
          }
          else {
            FUN_80099c40((double)FLOAT_803e5f40,puVar1,6,0x28);
          }
          FUN_8000bb38((uint)puVar1,0x58);
        }
      }
    }
    else {
      if (*(char *)((int)pfVar7 + 0x139) != '\0') {
        *(undefined4 *)(puVar1 + 6) = *(undefined4 *)(iVar6 + 8);
        *(undefined4 *)(puVar1 + 8) = *(undefined4 *)(iVar6 + 0xc);
        *(undefined4 *)(puVar1 + 10) = *(undefined4 *)(iVar6 + 0x10);
        *(undefined *)(puVar1 + 0x1b) = 0xff;
        *(undefined *)((int)pfVar7 + 0x139) = 0;
      }
      pfVar7[0x43] = pfVar7[0x42];
      dVar8 = FUN_80021794((float *)(iVar2 + 0x18),(float *)(puVar1 + 0xc));
      if (iVar3 == 0) {
        dVar8 = FUN_80293900(dVar8);
        pfVar7[0x42] = (float)dVar8;
      }
      else {
        dVar9 = FUN_80021794((float *)(iVar3 + 0x18),(float *)(puVar1 + 0xc));
        if (dVar9 <= dVar8) {
          dVar8 = FUN_80293900(dVar9);
          pfVar7[0x42] = (float)dVar8;
        }
        else {
          dVar8 = FUN_80293900(dVar8);
          pfVar7[0x42] = (float)dVar8;
        }
        param_2 = (double)pfVar7[0x42];
        local_34[2] = (int)*(byte *)(iVar6 + 0x1f);
        local_34[1] = 0x43300000;
        dVar8 = DOUBLE_803e5f58;
        if (param_2 < (double)(float)((double)CONCAT44(0x43300000,local_34[2]) - DOUBLE_803e5f58)) {
          in_r7 = **(int **)(iVar3 + 0x68);
          dVar8 = (double)(**(code **)(in_r7 + 0x28))(iVar3,puVar1,0,1);
        }
      }
      pfVar5 = (float *)0x0;
      iVar2 = FUN_80036974((int)puVar1,local_34,(int *)0x0,(uint *)0x0);
      if (iVar2 != 0) {
        if (iVar2 == 0x10) {
          dVar8 = (double)FUN_8002b128(puVar1,300);
        }
        else {
          pfVar5 = (float *)0x0;
          in_r7 = 0;
          in_r8 = 1;
          dVar8 = (double)FUN_8002ad08(puVar1,0xf,200,0,0,1);
          if (*(short *)(local_34[0] + 0x46) != 0x416) {
            if ((*(byte *)((int)pfVar7 + 0x137) & 0x10) == 0) {
              dVar8 = (double)FUN_8000bb38((uint)puVar1,0x9d);
            }
            *(byte *)((int)pfVar7 + 0x137) = *(byte *)((int)pfVar7 + 0x137) | 0x10;
          }
        }
      }
      FUN_801d0e2c(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(short *)puVar1,
                   pfVar7,iVar6,pfVar5,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

