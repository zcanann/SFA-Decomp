// Function: FUN_80159730
// Entry: 80159730
// Size: 976 bytes

void FUN_80159730(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_8028683c();
  psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar4 = (int)uVar12;
  uVar2 = (uint)*(byte *)(iVar4 + 0x33b);
  puVar9 = (&PTR_DAT_80320748)[uVar2 * 8];
  puVar8 = (&PTR_DAT_80320750)[uVar2 * 8];
  puVar7 = (&PTR_DAT_80320744)[uVar2 * 8];
  puVar6 = (&PTR_DAT_8032074c)[uVar2 * 8];
  if ((*(int *)(iVar4 + 0x29c) != 0) && (*(short *)(*(int *)(iVar4 + 0x29c) + 0x44) == 1)) {
    FUN_8001ff54();
  }
  if ((*(uint *)(iVar4 + 0x2dc) & 0x80000000) != 0) {
    if (*(char *)(iVar4 + 0x33b) == '\0') {
      (**(code **)(*DAT_803dd6d0 + 0x24))(0,0x6c,0);
    }
    if ((psVar3[0x23] == 0x6a2) && (*(int *)(psVar3 + 100) != 0)) {
      FUN_80220104(*(int *)(psVar3 + 100));
    }
    *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) | 0x10;
  }
  fVar1 = FLOAT_803e3840;
  dVar11 = (double)*(float *)(iVar4 + 0x328);
  dVar10 = (double)FLOAT_803e3840;
  if (((dVar11 != dVar10) && (*(char *)(iVar4 + 0x33f) != '\0')) &&
     (*(float *)(iVar4 + 0x328) = (float)(dVar11 - (double)FLOAT_803dc074),
     (double)*(float *)(iVar4 + 0x328) <= dVar10)) {
    *(float *)(iVar4 + 0x328) = fVar1;
    *(uint *)(iVar4 + 0x2dc) = *(uint *)(iVar4 + 0x2dc) | 0x40000000;
    *(char *)(iVar4 + 0x33c) =
         (char)*(undefined4 *)(puVar6 + (uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 0xc);
    *(byte *)(psVar3 + 0x72) = *(byte *)(iVar4 + 0x33c) & 1;
    *(undefined *)(iVar4 + 0x33f) = puVar6[(uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 10];
  }
  if ((*(uint *)(iVar4 + 0x2dc) & 0x40000000) != 0) {
    *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) & 0xcf;
    if ((psVar3[0x23] == 0x6a2) && (*(int *)(psVar3 + 100) != 0)) {
      FUN_80220104(*(int *)(psVar3 + 100));
    }
    if (*(byte *)(iVar4 + 0x33f) == 0) {
      iVar5 = (uint)*(ushort *)(iVar4 + 0x2a0) * 0xc;
      if ((byte)puVar7[iVar5 + 8] == 0) {
        if (0x4f < *(ushort *)(iVar4 + 0x2a4)) {
          *(undefined *)(iVar4 + 0x33a) = 0;
        }
        FUN_8014c594(psVar3,6,0x28,&DAT_803ad108);
        if (((*(uint *)(iVar4 + 0x2dc) &
             *(uint *)(puVar9 + (uint)*(byte *)(iVar4 + 0x33a) * 0xc + 4)) == 0) &&
           (puVar9[(uint)*(byte *)(iVar4 + 0x33a) * 0xc + 9] != '\0')) {
          *(undefined *)(iVar4 + 0x33a) = puVar9[(uint)*(byte *)(iVar4 + 0x33a) * 0xc + 9];
        }
        iVar5 = (uint)*(byte *)(iVar4 + 0x33a) * 0xc;
        dVar10 = (double)FUN_8014d504((double)*(float *)(puVar9 + iVar5),dVar11,param_3,param_4,
                                      param_5,param_6,param_7,param_8,(int)psVar3,iVar4,
                                      (uint)(byte)puVar9[iVar5 + 8],0,(uint)(byte)puVar9[iVar5 + 10]
                                      ,in_r8,in_r9,in_r10);
        *(undefined *)(iVar4 + 0x33a) = puVar9[(uint)*(byte *)(iVar4 + 0x33a) * 0xc + 9];
      }
      else {
        dVar10 = (double)FUN_8014d504((double)*(float *)(puVar7 + iVar5),dVar11,param_3,param_4,
                                      param_5,param_6,param_7,param_8,(int)psVar3,iVar4,
                                      (uint)(byte)puVar7[iVar5 + 8],0,(uint)(byte)puVar7[iVar5 + 10]
                                      ,in_r8,in_r9,in_r10);
      }
    }
    else {
      iVar5 = (uint)*(byte *)(iVar4 + 0x33f) * 0x10;
      dVar10 = (double)FUN_8014d504((double)*(float *)(puVar6 + iVar5),dVar11,param_3,param_4,
                                    param_5,param_6,param_7,param_8,(int)psVar3,iVar4,
                                    (uint)(byte)puVar6[iVar5 + 8],0,
                                    *(uint *)(puVar6 + iVar5 + 4) & 0xff,in_r8,in_r9,in_r10);
      *(char *)(iVar4 + 0x33c) =
           (char)*(undefined4 *)(puVar6 + (uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 0xc);
      *(byte *)(psVar3 + 0x72) = *(byte *)(iVar4 + 0x33c) & 1;
      *(undefined *)(iVar4 + 0x33f) = puVar6[(uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 9];
    }
  }
  *(undefined *)(*(int *)(psVar3 + 0x2a) + 0x6e) = 0;
  *(undefined *)(*(int *)(psVar3 + 0x2a) + 0x6f) = 0;
  iVar5 = 1;
  uVar2 = (uint)(byte)puVar8[8];
  puVar6 = puVar8;
  do {
    if (uVar2 == 0) {
LAB_80159a9c:
      if (((*(byte *)(iVar4 + 0x323) & 8) == 0) && ((*(byte *)(iVar4 + 0x33d) & 0x10) == 0)) {
        dVar11 = (double)*(float *)(*(int *)(iVar4 + 0x29c) + 0x14);
        dVar10 = (double)FUN_8014d3f4(psVar3,iVar4,0x1e,0);
      }
      FUN_80158188(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80286888();
      return;
    }
    if (psVar3[0x50] == (ushort)(byte)puVar6[0x14]) {
      *(char *)(*(int *)(psVar3 + 0x2a) + 0x6e) = (char)*(undefined4 *)(puVar8 + iVar5 * 0xc + 4);
      *(undefined *)(*(int *)(psVar3 + 0x2a) + 0x6f) = puVar8[iVar5 * 0xc + 9];
      if (*(char *)(*(int *)(psVar3 + 0x2a) + 0x6e) == '\x1f') {
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x40;
      }
      else {
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) & 0xffffffbf;
      }
      goto LAB_80159a9c;
    }
    iVar5 = iVar5 + 1;
    uVar2 = uVar2 - 1;
    puVar6 = puVar6 + 0xc;
  } while( true );
}

