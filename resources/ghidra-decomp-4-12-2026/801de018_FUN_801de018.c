// Function: FUN_801de018
// Entry: 801de018
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x801de1f0) */
/* WARNING: Removing unreachable block (ram,0x801de1e8) */
/* WARNING: Removing unreachable block (ram,0x801de1e0) */
/* WARNING: Removing unreachable block (ram,0x801de1d8) */
/* WARNING: Removing unreachable block (ram,0x801de040) */
/* WARNING: Removing unreachable block (ram,0x801de038) */
/* WARNING: Removing unreachable block (ram,0x801de030) */
/* WARNING: Removing unreachable block (ram,0x801de028) */

void FUN_801de018(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short *psVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char cVar4;
  char cVar5;
  int iVar6;
  int iVar7;
  double extraout_f1;
  double dVar8;
  double dVar9;
  
  psVar1 = (short *)FUN_80286830();
  dVar9 = extraout_f1;
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    cVar4 = '\x01';
    iVar7 = 0;
    for (cVar5 = '\0'; cVar5 < '\b'; cVar5 = cVar5 + '\x01') {
      iVar6 = *(int *)(psVar1 + 0x26);
      puVar3 = FUN_8002becc(0x38,0x27b);
      dVar8 = (double)FUN_802945e0();
      *(float *)(puVar3 + 4) = (float)(dVar9 * dVar8 + (double)*(float *)(psVar1 + 6));
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(psVar1 + 8);
      dVar8 = (double)FUN_80294964();
      *(float *)(puVar3 + 8) = (float)(dVar9 * dVar8 + (double)*(float *)(psVar1 + 10));
      *(undefined *)(puVar3 + 2) = *(undefined *)(iVar6 + 4);
      *(byte *)((int)puVar3 + 5) = *(byte *)(iVar6 + 5) & 0xfe | 4;
      *(undefined *)(puVar3 + 3) = *(undefined *)(iVar6 + 6);
      *(undefined *)((int)puVar3 + 7) = 0x1e;
      puVar3[0xc] = 0xffff;
      puVar3[0xd] = 0x64c;
      puVar3[0xe] = (&DAT_803286b0)[cVar4];
      puVar3[0x18] = *(undefined2 *)(cVar4 * 2 + -0x7fcd7960);
      *(char *)(puVar3 + 0x15) = (char)((uint)(*psVar1 + iVar7 + 0x8000) >> 8);
      *(undefined *)(puVar3 + 0x19) = 1;
      FUN_8002e088(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff,
                   0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      cVar4 = cVar4 + '\x01';
      if ('\a' < cVar4) {
        cVar4 = '\0';
      }
      iVar7 = iVar7 + 0x2000;
    }
  }
  FUN_8028687c();
  return;
}

