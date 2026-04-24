// Function: FUN_8028f920
// Entry: 8028f920
// Size: 1908 bytes

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Could not reconcile some variable overlaps */

int FUN_8028f920(code *param_1,undefined4 param_2,char *param_3,undefined4 param_4)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  uint *puVar4;
  undefined4 *puVar5;
  undefined8 *puVar6;
  byte **ppbVar7;
  int **ppiVar8;
  int *piVar9;
  undefined *puVar10;
  byte *pbVar11;
  undefined4 unaff_r22;
  undefined4 unaff_r23;
  undefined *puVar12;
  undefined *puVar13;
  int iVar14;
  uint unaff_r28;
  undefined8 uVar15;
  undefined local_2b8;
  char local_2b7 [3];
  undefined4 local_2b4;
  undefined4 local_2b0;
  int local_2ac;
  undefined *local_2a8;
  undefined4 local_2a4;
  undefined4 local_2a0;
  int local_29c;
  undefined *local_298;
  undefined4 local_294;
  undefined4 local_290;
  int local_28c;
  undefined *local_288;
  undefined4 local_284;
  undefined4 local_280;
  int local_27c;
  undefined *local_278;
  undefined4 local_274;
  undefined4 local_270;
  int local_26c;
  undefined *local_268;
  undefined4 local_264;
  undefined4 local_260;
  int local_25c;
  undefined *local_258;
  undefined4 local_254;
  undefined4 local_250;
  int local_24c;
  undefined *local_248;
  byte local_244 [511];
  undefined auStack69 [17];
  
  puVar12 = auStack69 + 1;
  iVar14 = 0;
  local_2b7[0] = ' ';
LAB_80290070:
  if (*param_3 == '\0') {
    return iVar14;
  }
  iVar2 = FUN_802915e4(param_3,0x25);
  if (iVar2 == 0) {
    iVar2 = FUN_802918a4(param_3);
    if (iVar2 == 0) {
      return iVar14 + iVar2;
    }
    iVar3 = (*param_1)(param_2,param_3);
    if (iVar3 != 0) {
      return iVar14 + iVar2;
    }
    return -1;
  }
  iVar14 = iVar14 + (iVar2 - (int)param_3);
  if ((iVar2 - (int)param_3 != 0) && (iVar3 = (*param_1)(param_2,param_3), iVar3 == 0)) {
    return -1;
  }
  param_3 = (char *)FUN_802910e0(iVar2,param_4,&local_254);
  if (local_250._1_1_ == 0x68) goto LAB_8028fef0;
  if (local_250._1_1_ < 0x68) {
    if (local_250._1_1_ == 0x58) goto LAB_8028fbac;
    if (local_250._1_1_ < 0x58) {
      if (local_250._1_1_ == 0x41) {
LAB_8028fd14:
        if (local_250._0_1_ == '\x05') {
          puVar6 = (undefined8 *)FUN_80285ea4(param_4,3);
          uVar15 = *puVar6;
        }
        else {
          puVar6 = (undefined8 *)FUN_80285ea4(param_4,3);
          uVar15 = *puVar6;
        }
        local_2b4 = local_254;
        local_2b0 = local_250;
        local_2ac = local_24c;
        local_2a8 = local_248;
        pbVar11 = (byte *)FUN_802908ac(uVar15,puVar12,&local_2b4);
        if (pbVar11 == (byte *)0x0) goto LAB_8028fef0;
        puVar10 = auStack69 + -(int)pbVar11;
      }
      else {
        if (0x40 < local_250._1_1_) {
          if ((0x47 < local_250._1_1_) || (local_250._1_1_ < 0x45)) goto LAB_8028fef0;
          goto LAB_8028fca8;
        }
        if (local_250._1_1_ != 0x25) goto LAB_8028fef0;
        pbVar11 = local_244;
        local_244[0] = 0x25;
        puVar10 = (undefined *)0x1;
      }
    }
    else if (local_250._1_1_ == 99) {
      pbVar11 = local_244;
      puVar5 = (undefined4 *)FUN_80285ea4(param_4,1);
      local_244[0] = (byte)*puVar5;
      puVar10 = (undefined *)0x1;
    }
    else {
      if (local_250._1_1_ < 99) {
        if (local_250._1_1_ != 0x61) goto LAB_8028fef0;
        goto LAB_8028fd14;
      }
      if (local_250._1_1_ < 0x65) goto LAB_8028fab0;
LAB_8028fca8:
      if (local_250._0_1_ == '\x05') {
        puVar6 = (undefined8 *)FUN_80285ea4(param_4,3);
        uVar15 = *puVar6;
      }
      else {
        puVar6 = (undefined8 *)FUN_80285ea4(param_4,3);
        uVar15 = *puVar6;
      }
      local_2a4 = local_254;
      local_2a0 = local_250;
      local_29c = local_24c;
      local_298 = local_248;
      pbVar11 = (byte *)FUN_80290094(uVar15,puVar12,&local_2a4);
      if (pbVar11 == (byte *)0x0) goto LAB_8028fef0;
      puVar10 = auStack69 + -(int)pbVar11;
    }
  }
  else {
    if (local_250._1_1_ == 0x74) goto LAB_8028fef0;
    if (local_250._1_1_ < 0x74) {
      if (local_250._1_1_ != 0x6f) {
        if (local_250._1_1_ < 0x6f) {
          if (local_250._1_1_ < 0x6e) {
            if (0x69 < local_250._1_1_) goto LAB_8028fef0;
LAB_8028fab0:
            if (local_250._0_1_ == '\x03') {
              puVar4 = (uint *)FUN_80285ea4(param_4,1);
              unaff_r28 = *puVar4;
            }
            else if (local_250._0_1_ == '\x04') {
              puVar5 = (undefined4 *)FUN_80285ea4(param_4,2);
              unaff_r22 = *puVar5;
              unaff_r23 = puVar5[1];
            }
            else {
              puVar4 = (uint *)FUN_80285ea4(param_4,1);
              unaff_r28 = *puVar4;
            }
            if (local_250._0_1_ == '\x02') {
              unaff_r28 = (uint)(short)unaff_r28;
            }
            if (local_250._0_1_ == '\x01') {
              unaff_r28 = (uint)(char)unaff_r28;
            }
            if (local_250._0_1_ == '\x04') {
              local_264 = local_254;
              local_260 = local_250;
              local_25c = local_24c;
              local_258 = local_248;
              pbVar11 = (byte *)FUN_80290be4(unaff_r22,unaff_r23,puVar12,&local_264);
            }
            else {
              local_274 = local_254;
              local_270 = local_250;
              local_26c = local_24c;
              local_268 = local_248;
              pbVar11 = (byte *)FUN_80290ec0(unaff_r28,puVar12,&local_274);
            }
            if (pbVar11 == (byte *)0x0) goto LAB_8028fef0;
            puVar10 = auStack69 + -(int)pbVar11;
            goto LAB_8028ff30;
          }
          ppiVar8 = (int **)FUN_80285ea4(param_4,1);
          piVar9 = *ppiVar8;
          if (local_250._0_1_ == 2) {
            *(short *)piVar9 = (short)iVar14;
          }
          else if (local_250._0_1_ < 2) {
            if (local_250._0_1_ == 0) {
              *piVar9 = iVar14;
            }
          }
          else if (local_250._0_1_ == 4) {
            piVar9[1] = iVar14;
            *piVar9 = iVar14 >> 0x1f;
          }
          else if (local_250._0_1_ < 4) {
            *piVar9 = iVar14;
          }
          goto LAB_80290070;
        }
        if (local_250._1_1_ < 0x73) goto LAB_8028fef0;
        if (local_250._0_1_ == '\x06') {
          puVar5 = (undefined4 *)FUN_80285ea4(param_4,1);
          puVar10 = (undefined *)*puVar5;
          if (puVar10 == (undefined *)0x0) {
            puVar10 = &DAT_803dc640;
          }
          iVar3 = FUN_8028f0e4(local_244,puVar10,0x200);
          if (iVar3 < 0) goto LAB_8028fef0;
          pbVar11 = local_244;
        }
        else {
          ppbVar7 = (byte **)FUN_80285ea4(param_4,1);
          pbVar11 = *ppbVar7;
        }
        puVar13 = local_248;
        if (pbVar11 == (byte *)0x0) {
          pbVar11 = &DAT_802c2af8;
        }
        if ((char)local_254 == '\0') {
          if (local_254._2_1_ == '\0') {
            puVar10 = (undefined *)FUN_802918a4(pbVar11);
          }
          else {
            iVar2 = FUN_8028f2a0(pbVar11,0,local_248);
            puVar10 = puVar13;
            if (iVar2 != 0) {
              puVar10 = (undefined *)(iVar2 - (int)pbVar11);
            }
          }
        }
        else {
          puVar10 = (undefined *)(uint)*pbVar11;
          pbVar11 = pbVar11 + 1;
          if ((local_254._2_1_ != '\0') && ((int)local_248 < (int)puVar10)) {
            puVar10 = puVar13;
          }
        }
        goto LAB_8028ff30;
      }
    }
    else if ((local_250._1_1_ != 0x78) && ((0x77 < local_250._1_1_ || (0x75 < local_250._1_1_))))
    goto LAB_8028fef0;
LAB_8028fbac:
    if (local_250._0_1_ == '\x03') {
      puVar4 = (uint *)FUN_80285ea4(param_4,1);
      unaff_r28 = *puVar4;
    }
    else if (local_250._0_1_ == '\x04') {
      puVar5 = (undefined4 *)FUN_80285ea4(param_4,2);
      unaff_r22 = *puVar5;
      unaff_r23 = puVar5[1];
    }
    else {
      puVar4 = (uint *)FUN_80285ea4(param_4,1);
      unaff_r28 = *puVar4;
    }
    if (local_250._0_1_ == '\x02') {
      unaff_r28 = unaff_r28 & 0xffff;
    }
    if (local_250._0_1_ == '\x01') {
      unaff_r28 = unaff_r28 & 0xff;
    }
    if (local_250._0_1_ == '\x04') {
      local_284 = local_254;
      local_280 = local_250;
      local_27c = local_24c;
      local_278 = local_248;
      pbVar11 = (byte *)FUN_80290be4(unaff_r22,unaff_r23,puVar12,&local_284);
    }
    else {
      local_294 = local_254;
      local_290 = local_250;
      local_28c = local_24c;
      local_288 = local_248;
      pbVar11 = (byte *)FUN_80290ec0(unaff_r28,puVar12,&local_294);
    }
    if (pbVar11 == (byte *)0x0) {
LAB_8028fef0:
      iVar3 = FUN_802918a4(iVar2);
      if (iVar3 == 0) {
        return iVar14 + iVar3;
      }
      iVar2 = (*param_1)(param_2,iVar2);
      if (iVar2 != 0) {
        return iVar14 + iVar3;
      }
      return -1;
    }
    puVar10 = auStack69 + -(int)pbVar11;
  }
LAB_8028ff30:
  puVar13 = puVar10;
  if (local_254._0_1_ != '\0') {
    local_2b7[0] = ' ';
    if (local_254._0_1_ == '\x02') {
      local_2b7[0] = '0';
    }
    bVar1 = *pbVar11;
    if ((((bVar1 == 0x2b) || (bVar1 == 0x2d)) || (bVar1 == 0x20)) && (local_2b7[0] == '0')) {
      iVar2 = (*param_1)(param_2,pbVar11,1);
      if (iVar2 == 0) {
        return -1;
      }
      pbVar11 = pbVar11 + 1;
      puVar13 = puVar10 + -1;
    }
    for (; (int)puVar10 < local_24c; puVar10 = puVar10 + 1) {
      iVar2 = (*param_1)(param_2,local_2b7,1);
      if (iVar2 == 0) {
        return -1;
      }
    }
  }
  if ((puVar13 != (undefined *)0x0) && (iVar2 = (*param_1)(param_2,pbVar11,puVar13), iVar2 == 0)) {
    return -1;
  }
  if (local_254._0_1_ == '\0') {
    for (; (int)puVar10 < local_24c; puVar10 = puVar10 + 1) {
      local_2b8 = 0x20;
      iVar2 = (*param_1)(param_2,&local_2b8,1);
      if (iVar2 == 0) {
        return -1;
      }
    }
  }
  iVar14 = iVar14 + (int)puVar10;
  goto LAB_80290070;
}

