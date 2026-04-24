// Function: FUN_802b92ac
// Entry: 802b92ac
// Size: 1428 bytes

void FUN_802b92ac(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined2 *puVar1;
  uint uVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  float local_48;
  float local_44;
  float local_40;
  undefined auStack_3c [12];
  float local_30;
  float local_2c;
  float local_28;
  
  puVar1 = (undefined2 *)FUN_80286840();
  iVar7 = *(int *)(puVar1 + 0x5c);
  iVar6 = *(int *)(puVar1 + 0x26);
  iVar5 = *(int *)(iVar7 + 0x40c);
  dVar9 = (double)*(float *)(iVar5 + 0x10);
  dVar8 = (double)FLOAT_803e8e18;
  if ((dVar9 != dVar8) &&
     (*(float *)(iVar5 + 0x10) = (float)(dVar9 - (double)FLOAT_803dc074),
     (double)*(float *)(iVar5 + 0x10) <= dVar8)) {
    dVar8 = (double)FUN_8002cc9c(dVar8,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,
                                 (int)puVar1);
  }
  if ((puVar1[0x23] != 0x27c) || ((int)*(short *)(iVar7 + 0x3f2) == 0xffffffff)) goto LAB_802b9624;
  iVar3 = *(int *)(iVar6 + 0x14);
  if (iVar3 == 0x499ad) {
LAB_802b95d4:
    uVar2 = FUN_80020078((int)*(short *)(iVar7 + 0x3f2));
    uVar2 = countLeadingZeros(uVar2);
    *(uint *)(puVar1 + 0x7a) = uVar2 >> 5;
  }
  else {
    if (0x499ac < iVar3) {
      if (iVar3 < 0x499b3) {
        if (iVar3 < 0x499b0) goto LAB_802b93a4;
        uVar2 = FUN_80020078(0xc46);
        if ((uVar2 == 0) || (uVar2 = FUN_80020078((int)*(short *)(iVar7 + 0x3f2)), uVar2 != 0)) {
          *(undefined4 *)(puVar1 + 0x7a) = 1;
        }
        else {
          iVar3 = FUN_8002e1ac(0x499b6);
          if ((iVar3 != 0) &&
             (dVar8 = (double)FUN_800217c8((float *)(puVar1 + 0xc),(float *)(iVar3 + 0x18)),
             dVar8 < (double)FLOAT_803e8eac)) {
            FUN_800201ac((int)*(short *)(iVar7 + 0x3f2),1);
            local_30 = FLOAT_803e8e18;
            local_2c = FLOAT_803e8eb0;
            local_28 = FLOAT_803e8e18;
            for (cVar4 = '\x14'; cVar4 != '\0'; cVar4 = cVar4 + -1) {
              dVar9 = (double)FLOAT_803e8eb0;
              FUN_80097568((double)FLOAT_803e8e68,dVar9,puVar1,5,5,6,100,(int)auStack_3c,0);
            }
            uVar2 = FUN_80020078(0xc3e);
            if (((uVar2 == 0) || (uVar2 = FUN_80020078(0xc3f), uVar2 == 0)) ||
               (uVar2 = FUN_80020078(0xc40), uVar2 == 0)) {
              FUN_8000bb38(0,0x409);
            }
            else {
              FUN_8000bb38(0,0x7e);
            }
          }
          uVar2 = FUN_80020078((int)*(short *)(iVar7 + 0x3f2));
          *(uint *)(puVar1 + 0x7a) = uVar2;
        }
        goto LAB_802b95e4;
      }
      goto LAB_802b95d4;
    }
    if (iVar3 < 0x49942) {
      if (iVar3 < 0x4993f) goto LAB_802b95d4;
      uVar2 = FUN_80020078(0xc44);
      if (uVar2 == 0) {
        *(undefined4 *)(puVar1 + 0x7a) = 1;
      }
      else {
        uVar2 = FUN_80020078((int)*(short *)(iVar7 + 0x3f2));
        *(uint *)(puVar1 + 0x7a) = uVar2;
      }
    }
    else {
      if (iVar3 < 0x499ac) goto LAB_802b95d4;
LAB_802b93a4:
      uVar2 = FUN_80020078(0xc42);
      if ((uVar2 == 0) || (uVar2 = FUN_80020078((int)*(short *)(iVar7 + 0x3f2)), uVar2 != 0)) {
        *(undefined4 *)(puVar1 + 0x7a) = 1;
      }
      else {
        iVar3 = FUN_8002e1ac(0x499b5);
        if ((iVar3 != 0) &&
           (dVar8 = (double)FUN_800217c8((float *)(puVar1 + 0xc),(float *)(iVar3 + 0x18)),
           dVar8 < (double)FLOAT_803e8eac)) {
          FUN_800201ac((int)*(short *)(iVar7 + 0x3f2),1);
          local_30 = FLOAT_803e8e18;
          local_2c = FLOAT_803e8eb0;
          local_28 = FLOAT_803e8e18;
          for (cVar4 = '\x14'; cVar4 != '\0'; cVar4 = cVar4 + -1) {
            dVar9 = (double)FLOAT_803e8eb0;
            FUN_80097568((double)FLOAT_803e8e68,dVar9,puVar1,5,5,6,100,(int)auStack_3c,0);
          }
          uVar2 = FUN_80020078(0xc3b);
          if (((uVar2 == 0) || (uVar2 = FUN_80020078(0xc3c), uVar2 == 0)) ||
             (uVar2 = FUN_80020078(0xc3d), uVar2 == 0)) {
            FUN_8000bb38(0,0x409);
          }
          else {
            FUN_8000bb38(0,0x7e);
          }
        }
        uVar2 = FUN_80020078((int)*(short *)(iVar7 + 0x3f2));
        *(uint *)(puVar1 + 0x7a) = uVar2;
      }
    }
  }
LAB_802b95e4:
  if (*(int *)(puVar1 + 0x7a) == 0) {
    dVar8 = (double)FUN_80036018((int)puVar1);
    puVar1[3] = puVar1[3] & 0xbfff;
  }
  else {
    dVar8 = (double)FUN_80035ff8((int)puVar1);
    puVar1[3] = puVar1[3] | 0x4000;
  }
LAB_802b9624:
  if (*(int *)(puVar1 + 0x7a) == 0) {
    FUN_802b8d44(dVar8,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar1,iVar7);
    if ((*(ushort *)(iVar7 + 0x400) & 2) != 0) {
      FUN_802b89dc((int)puVar1,iVar7,iVar5);
      FUN_802b8c30(puVar1);
      *(undefined4 *)(puVar1 + 0x7c) = 0;
      *(ushort *)(iVar7 + 0x400) = *(ushort *)(iVar7 + 0x400) & 0xfffd;
    }
    FUN_802b8e18(puVar1,iVar7,iVar7);
    if (((*(byte *)(iVar7 + 0x404) & 1) != 0) && ((puVar1[0x58] & 0x800) != 0)) {
      iVar6 = *(int *)(iVar7 + 0x40c);
      *(float *)(iVar6 + 0xc) = *(float *)(iVar6 + 0xc) - FLOAT_803dc074;
      if (FLOAT_803e8e18 < *(float *)(iVar6 + 0xc)) {
        uVar2 = 0;
      }
      else {
        uVar2 = 3;
        *(float *)(iVar6 + 0xc) = *(float *)(iVar6 + 0xc) + FLOAT_803e8e58;
      }
      local_48 = FLOAT_803e8e18;
      local_44 = FLOAT_803e8e5c;
      local_40 = FLOAT_803e8e18;
      FUN_8000da78((uint)puVar1,0x455);
      FUN_80098da4(puVar1,3,uVar2,0,&local_48);
    }
    *(float *)(iVar5 + 0x14) = *(float *)(iVar5 + 0x14) - FLOAT_803dc074;
  }
  else if ((((*(int *)(iVar6 + 0x14) == 0x499b5) && (uVar2 = FUN_80020078(0xc42), uVar2 != 0)) &&
           ((uVar2 = FUN_80020078(0xc3b), uVar2 == 0 ||
            ((uVar2 = FUN_80020078(0xc3c), uVar2 == 0 || (uVar2 = FUN_80020078(0xc3d), uVar2 == 0)))
            ))) || ((*(int *)(iVar6 + 0x14) == 0x499b6 &&
                    ((uVar2 = FUN_80020078(0xc46), uVar2 != 0 &&
                     (((uVar2 = FUN_80020078(0xc3e), uVar2 == 0 ||
                       (uVar2 = FUN_80020078(0xc3f), uVar2 == 0)) ||
                      (uVar2 = FUN_80020078(0xc40), uVar2 == 0)))))))) {
    local_30 = FLOAT_803e8e18;
    local_2c = FLOAT_803e8eb4;
    local_28 = FLOAT_803e8e18;
    FUN_800979c0((double)FLOAT_803e8eb8,(double)FLOAT_803e8eac,(double)FLOAT_803e8eac,
                 (double)FLOAT_803e8ebc,puVar1,5,1,6,0x32,(int)auStack_3c,0);
  }
  FUN_8028688c();
  return;
}

