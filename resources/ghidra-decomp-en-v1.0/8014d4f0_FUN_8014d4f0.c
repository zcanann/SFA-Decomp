// Function: FUN_8014d4f0
// Entry: 8014d4f0
// Size: 1236 bytes

void FUN_8014d4f0(void)

{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  
  puVar2 = (undefined2 *)FUN_802860dc();
  iVar8 = *(int *)(puVar2 + 0x5c);
  iVar7 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_8002b9ac();
  iVar4 = FUN_80014940();
  if (iVar4 != 4) {
    if ((*(uint *)(iVar8 + 0x2e4) & 0x8000006) == 0) {
      iVar4 = FUN_8005b16c((double)*(float *)(puVar2 + 6),(double)*(float *)(puVar2 + 10));
      if (iVar4 == 0) goto LAB_8014d9cc;
    }
    else {
      iVar4 = FUN_8005b2fc((double)*(float *)(puVar2 + 6),(double)*(float *)(puVar2 + 8),
                           (double)*(float *)(puVar2 + 10));
      if (iVar4 == -1) goto LAB_8014d9cc;
    }
    iVar4 = FUN_8002b044(puVar2);
    if (iVar4 == 0) {
      if (*(int *)(iVar8 + 0x29c) == 0) {
        uVar5 = FUN_8002b9ec();
        *(undefined4 *)(iVar8 + 0x29c) = uVar5;
      }
      else if ((*(ushort *)(*(int *)(iVar8 + 0x29c) + 0xb0) & 0x40) != 0) {
        uVar5 = FUN_8002b9ec();
        *(undefined4 *)(iVar8 + 0x29c) = uVar5;
      }
      *(undefined4 *)(iVar8 + 0x2e0) = *(undefined4 *)(iVar8 + 0x2dc);
      FUN_8014a058(puVar2,iVar8);
      if (((*(uint *)(iVar8 + 0x2dc) & 1) == 0) || ((*(uint *)(iVar8 + 0x2dc) & 2) != 0)) {
        if (*(int *)(puVar2 + 0x7a) != 0) {
          if (*(short *)(iVar7 + 0x1a) == -1) {
            if (*(short *)(iVar7 + 0x18) == -1) {
              if (((((*(int *)(iVar7 + 0x14) == -1) || (*(short *)(iVar7 + 0x2c) == 0)) ||
                   (iVar4 = (**(code **)(*DAT_803dcaac + 0x68))(), iVar4 == 0)) ||
                  (((*(uint *)(iVar8 + 0x2dc) & 0x800) != 0 || (iVar4 = FUN_8002b9ec(), iVar4 == 0))
                  )) || (dVar9 = (double)FUN_800216d0(iVar4 + 0x18,iVar7 + 8),
                        dVar9 <= (double)FLOAT_803e2600)) goto LAB_8014d9cc;
              FUN_8014d9e4(puVar2,iVar7,0);
              *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) | 0x1000;
              *(uint *)(iVar8 + 0x2e0) = *(uint *)(iVar8 + 0x2e0) & 0xffffefff;
            }
            else {
              iVar4 = FUN_8001ffb4();
              if (((iVar4 != 0) || ((*(uint *)(iVar8 + 0x2dc) & 0x800) != 0)) ||
                 ((iVar4 = FUN_8002b9ec(), iVar4 == 0 ||
                  (dVar9 = (double)FUN_800216d0(iVar4 + 0x18,iVar7 + 8),
                  dVar9 <= (double)FLOAT_803e2600)))) goto LAB_8014d9cc;
              FUN_8014d9e4(puVar2,iVar7,0);
              *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) | 0x1000;
              *(uint *)(iVar8 + 0x2e0) = *(uint *)(iVar8 + 0x2e0) & 0xffffefff;
            }
          }
          else {
            iVar4 = FUN_8001ffb4();
            if (((((iVar4 == 0) || ((*(uint *)(iVar8 + 0x2dc) & 0x800) != 0)) ||
                 ((*(uint *)(iVar8 + 0x2dc) & 0x1000) == 0)) ||
                ((iVar4 = FUN_8002b9ec(), *(short *)(iVar7 + 0x18) != -1 &&
                 (iVar6 = FUN_8001ffb4(), iVar6 != 0)))) ||
               ((iVar4 == 0 ||
                (dVar9 = (double)FUN_800216d0(iVar4 + 0x18,iVar7 + 8),
                dVar9 <= (double)FLOAT_803e2600)))) goto LAB_8014d9cc;
            FUN_8014d9e4(puVar2,iVar7,0);
            *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) | 0x1000;
            *(uint *)(iVar8 + 0x2e0) = *(uint *)(iVar8 + 0x2e0) & 0xffffefff;
          }
        }
        if ((*(uint *)(iVar8 + 0x2dc) & 0x8000) != 0) {
          FUN_8011f38c(0);
          (**(code **)(*DAT_803dcaa8 + 0x20))(puVar2,iVar8 + 4);
          *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & 0xffff7ffc;
          if ((*(uint *)(iVar8 + 0x2e4) & 0x20000) != 0) {
            iVar4 = *(int *)(puVar2 + 0x26);
            *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 8);
            *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0xc);
            *(undefined4 *)(puVar2 + 10) = *(undefined4 *)(iVar4 + 0x10);
            puVar2[2] = 0;
            puVar2[1] = 0;
            *puVar2 = (short)((int)*(char *)(iVar4 + 0x2a) << 8);
            fVar1 = FLOAT_803e2574;
            *(float *)(puVar2 + 0x12) = FLOAT_803e2574;
            *(float *)(puVar2 + 0x14) = fVar1;
            *(float *)(puVar2 + 0x16) = fVar1;
          }
        }
        if ((*(uint *)(iVar8 + 0x2e4) & 0x80000) != 0) {
          if ((iVar3 == 0) || (iVar4 = FUN_8001ffb4(0x9e), iVar4 == 0)) {
            *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 0x10;
          }
          else {
            *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xef;
          }
          if ((iVar3 != 0) && ((*(byte *)((int)puVar2 + 0xaf) & 4) != 0)) {
            (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,puVar2,1,2);
          }
        }
        FUN_801490c8(puVar2,iVar8,0);
        if ((*(uint *)(iVar8 + 0x2dc) & 0x1800) == 0) {
          FUN_8014bc98(puVar2,iVar8);
          FUN_8014b878(puVar2,iVar8);
        }
        FUN_8014a9f0(puVar2,iVar8);
      }
      else if (*(char *)(iVar7 + 0x2e) != -1) {
        if ((iVar7 != 0) && ((*(byte *)(iVar7 + 0x2b) & 8) != 0)) {
          *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar7 + 8);
          *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar7 + 0xc);
          *(undefined4 *)(puVar2 + 10) = *(undefined4 *)(iVar7 + 0x10);
        }
        (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar7 + 0x2e),puVar2,0xffffffff);
        *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) | 2;
        *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & 0xfffffffe;
      }
    }
    else {
      FUN_801490c8(puVar2,iVar8,1);
    }
  }
LAB_8014d9cc:
  FUN_80286128();
  return;
}

