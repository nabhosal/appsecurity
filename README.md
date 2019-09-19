# How to secure JAR/APP, and make it active/usable for specific duration 

We come across a requirement of deploying our important jar on the client environment, yup it is a very common scenario.  But we wanted the jar to be usable for a specific duration & reverse engineering of the jar should be very hard to do.
For making reverse engineering very hard, we used code obfuscate & dynamic proxy to hide important class and audit method invocation through a proxy.
But the challenge of sharing a jar & making it usable for the specific duration is a very important business requirement. Since once the jar is shared we don’t have any control, and we wanted it to be non-usable if unfortunately, someone gets access to the jar he should not be able to use it.

The problem can be divided into two parts,
1. Share Jar expiration time ( i.e TCert ) separately and must be temper free
2. The dependency of Jar on system/machine time

We build certificate and shared it separately to our client, the certificate is a cipher containing TCert time. We used asymmetric encryption (RSA) technique to build certificate, a cipher is created using PrivateKey and PublicKey is hardcoded in SecurityContext class for decrypting the certificate/cipher. It’s similar to a signature verification technique without exposing certificate content.

If jar depends on system time then by just tempering system time, a jar can be easily compromised. We completely avoid using system time, it relies on the Network Time Protocol (NTP) server to give the correct time. It periodically refreshes (Tapp time) from NTP servers.

##### How to create a new Certificate
```java
String rawdata = "2019-06-01T18:30:27.298||other important stuff||2019-06-05T12:59:27.298||2019-06-04T18:30:27.298";
        CertificateUtil certificateUtil = CertificateUtil.getInstance();
        Triplet<String, String, String> certificate = certificateUtil.buildCertificateForData(rawdata);

        System.out.println("Public Key: "+certificate.$1());
        System.out.println("Obfuscated Public Key: "+ Obfuscator.getObfuscatedCode(certificate.$1()));
        System.out.println("Private Key: "+certificate.$2());
        System.out.println("Certificate: "+certificate.$3());

/*

Public Key: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjQH5WhNFu7rhi14dMIp7YjAuKbsmXl2jAjvDqUb2tCbWFu6uqmPk2NKO6Z8lCKynKEKWGwohl/QihcZgMUi1A/RV5TbWANLLOjLMrGvxi4VVljGIOSLnnPfvEuJTYwAq+DVfFNEHWi0p89cfglhPT2rda54ty2qSuciaZrLJJQq1hPQUAzJxDRYAGwmMTDww0YGksGZVFOoTkHKimMh6mhxZoXp9AfoJuho/+uLr2AJh5JFYW3aRFuF/JV7Flgb5Z6fNrE51a+JcmagPQNFeffO7BNyICQ4KBZ2v+V6b6yQZhh3b2JruBOYRLsHXFivJtnotVaD14m4l19URz8qQMwIDAQAB
Obfuscated Public Key: (new Object() {int t;public String toString() {byte[] buf = new byte[392];t = -101370542;buf[0] = (byte) (t >>> 10);t = -1994077654;buf[1] = (byte) (t >>> 15);t = 837887004;buf[2] = (byte) (t >>> 10);t = -1232804141;buf[3] = (byte) (t >>> 17);t = 1487485647;buf[4] = (byte) (t >>> 13);t = -921514681;buf[5] = (byte) (t >>> 5);t = -1635594503;buf[6] = (byte) (t >>> 17);t = -635790269;buf[7] = (byte) (t >>> 9);t = -963592402;buf[8] = (byte) (t >>> 14);t = -2111726437;buf[9] = (byte) (t >>> 10);t = -1697435658;buf[10] = (byte) (t >>> 22);t = -148946290;buf[11] = (byte) (t >>> 20);t = -2140655607;buf[12] = (byte) (t >>> 16);t = -1242798988;buf[13] = (byte) (t >>> 23);t = 1252216761;buf[14] = (byte) (t >>> 11);t = 1200748922;buf[15] = (byte) (t >>> 14);t = 1094273967;buf[16] = (byte) (t >>> 16);t = 1681715057;buf[17] = (byte) (t >>> 9);t = -1863765799;buf[18] = (byte) (t >>> 8);t = 636475922;buf[19] = (byte) (t >>> 3);t = 873664418;buf[20] = (byte) (t >>> 20);t = -514565531;buf[21] = (byte) (t >>> 14);t = -1410886572;buf[22] = (byte) (t >>> 4);t = 818225292;buf[23] = (byte) (t >>> 1);t = 546728730;buf[24] = (byte) (t >>> 23);t = -68547336;buf[25] = (byte) (t >>> 11);t = -157413286;buf[26] = (byte) (t >>> 17);t = -1914148595;buf[27] = (byte) (t >>> 2);t = -1151202943;buf[28] = (byte) (t >>> 11);t = 1696153638;buf[29] = (byte) (t >>> 20);t = -675166673;buf[30] = (byte) (t >>> 11);t = 679354536;buf[31] = (byte) (t >>> 7);t = 81542390;buf[32] = (byte) (t >>> 20);t = -454779714;buf[33] = (byte) (t >>> 12);t = 1986696013;buf[34] = (byte) (t >>> 9);t = 1594050636;buf[35] = (byte) (t >>> 5);t = -721807158;buf[36] = (byte) (t >>> 11);t = 871381476;buf[37] = (byte) (t >>> 23);t = -785443440;buf[38] = (byte) (t >>> 18);t = -1977924521;buf[39] = (byte) (t >>> 19);t = -1164033787;buf[40] = (byte) (t >>> 8);t = 1727441039;buf[41] = (byte) (t >>> 7);t = 1586226632;buf[42] = (byte) (t >>> 17);t = -1325105956;buf[43] = (byte) (t >>> 18);t = -1256956958;buf[44] = (byte) (t >>> 23);t = 1649267996;buf[45] = (byte) (t >>> 4);t = -1576721862;buf[46] = (byte) (t >>> 10);t = -508907778;buf[47] = (byte) (t >>> 19);t = 628907598;buf[48] = (byte) (t >>> 20);t = 123839353;buf[49] = (byte) (t >>> 10);t = -1354417888;buf[50] = (byte) (t >>> 10);t = -356752279;buf[51] = (byte) (t >>> 4);t = 491725933;buf[52] = (byte) (t >>> 22);t = 1066255435;buf[53] = (byte) (t >>> 14);t = -2075466460;buf[54] = (byte) (t >>> 9);t = 1855670170;buf[55] = (byte) (t >>> 11);t = 2100610325;buf[56] = (byte) (t >>> 15);t = 1022780360;buf[57] = (byte) (t >>> 9);t = -544564831;buf[58] = (byte) (t >>> 3);t = 1678411842;buf[59] = (byte) (t >>> 24);t = 2058133146;buf[60] = (byte) (t >>> 1);t = -358985842;buf[61] = (byte) (t >>> 11);t = 1237528194;buf[62] = (byte) (t >>> 18);t = 253481958;buf[63] = (byte) (t >>> 15);t = -1050235680;buf[64] = (byte) (t >>> 18);t = -227874550;buf[65] = (byte) (t >>> 16);t = 1671970809;buf[66] = (byte) (t >>> 13);t = 2112073554;buf[67] = (byte) (t >>> 11);t = -716420172;buf[68] = (byte) (t >>> 8);t = 412066818;buf[69] = (byte) (t >>> 22);t = -1152491062;buf[70] = (byte) (t >>> 13);t = 1969317585;buf[71] = (byte) (t >>> 4);t = -1198117516;buf[72] = (byte) (t >>> 14);t = -949123828;buf[73] = (byte) (t >>> 13);t = 390600905;buf[74] = (byte) (t >>> 2);t = 820816085;buf[75] = (byte) (t >>> 1);t = -2019016710;buf[76] = (byte) (t >>> 13);t = -851351532;buf[77] = (byte) (t >>> 21);t = -1208151827;buf[78] = (byte) (t >>> 1);t = 1358986440;buf[79] = (byte) (t >>> 22);t = 73653133;buf[80] = (byte) (t >>> 3);t = 850026202;buf[81] = (byte) (t >>> 19);t = 180718465;buf[82] = (byte) (t >>> 17);t = -1441200066;buf[83] = (byte) (t >>> 15);t = -1933959225;buf[84] = (byte) (t >>> 15);t = -2143674511;buf[85] = (byte) (t >>> 11);t = 509792808;buf[86] = (byte) (t >>> 16);t = -1721908458;buf[87] = (byte) (t >>> 18);t = 1226477640;buf[88] = (byte) (t >>> 18);t = 216866114;buf[89] = (byte) (t >>> 6);t = 1834014947;buf[90] = (byte) (t >>> 10);t = -1259728621;buf[91] = (byte) (t >>> 17);t = -31693311;buf[92] = (byte) (t >>> 14);t = 225237831;buf[93] = (byte) (t >>> 6);t = -448749975;buf[94] = (byte) (t >>> 18);t = 711929194;buf[95] = (byte) (t >>> 5);t = -1112782645;buf[96] = (byte) (t >>> 2);t = -18232752;buf[97] = (byte) (t >>> 13);t = 1903240672;buf[98] = (byte) (t >>> 7);t = -465405723;buf[99] = (byte) (t >>> 11);t = -1963596082;buf[100] = (byte) (t >>> 5);t = -521751295;buf[101] = (byte) (t >>> 9);t = 943687911;buf[102] = (byte) (t >>> 24);t = -1398054624;buf[103] = (byte) (t >>> 11);t = 697363642;buf[104] = (byte) (t >>> 14);t = 86887506;buf[105] = (byte) (t >>> 18);t = -2022069491;buf[106] = (byte) (t >>> 16);t = -1015740849;buf[107] = (byte) (t >>> 19);t = -2127712879;buf[108] = (byte) (t >>> 18);t = 191700246;buf[109] = (byte) (t >>> 2);t = -2053558441;buf[110] = (byte) (t >>> 10);t = 730597910;buf[111] = (byte) (t >>> 23);t = 1761220482;buf[112] = (byte) (t >>> 21);t = -205689644;buf[113] = (byte) (t >>> 19);t = 1043195710;buf[114] = (byte) (t >>> 13);t = 1567712911;buf[115] = (byte) (t >>> 4);t = 693089904;buf[116] = (byte) (t >>> 7);t = 2007192313;buf[117] = (byte) (t >>> 4);t = 978450094;buf[118] = (byte) (t >>> 16);t = 325679592;buf[119] = (byte) (t >>> 16);t = -580323855;buf[120] = (byte) (t >>> 16);t = -2042725084;buf[121] = (byte) (t >>> 20);t = -1867688311;buf[122] = (byte) (t >>> 6);t = 1508274850;buf[123] = (byte) (t >>> 12);t = 2053760720;buf[124] = (byte) (t >>> 19);t = 1253051857;buf[125] = (byte) (t >>> 21);t = 592347938;buf[126] = (byte) (t >>> 19);t = 140294243;buf[127] = (byte) (t >>> 1);t = -2142220660;buf[128] = (byte) (t >>> 14);t = -615202865;buf[129] = (byte) (t >>> 10);t = -1803046205;buf[130] = (byte) (t >>> 22);t = 364537093;buf[131] = (byte) (t >>> 22);t = 1862743383;buf[132] = (byte) (t >>> 8);t = 72631330;buf[133] = (byte) (t >>> 16);t = 1678894631;buf[134] = (byte) (t >>> 4);t = -1411469739;buf[135] = (byte) (t >>> 23);t = 1457770759;buf[136] = (byte) (t >>> 2);t = -1584116063;buf[137] = (byte) (t >>> 8);t = -927649536;buf[138] = (byte) (t >>> 10);t = 1059858037;buf[139] = (byte) (t >>> 7);t = 1407972840;buf[140] = (byte) (t >>> 22);t = 582701689;buf[141] = (byte) (t >>> 11);t = 616883314;buf[142] = (byte) (t >>> 20);t = -1834549718;buf[143] = (byte) (t >>> 15);t = -1711159145;buf[144] = (byte) (t >>> 10);t = 374473848;buf[145] = (byte) (t >>> 4);t = 1176348054;buf[146] = (byte) (t >>> 14);t = 2005548110;buf[147] = (byte) (t >>> 20);t = -139715991;buf[148] = (byte) (t >>> 6);t = 1617479299;buf[149] = (byte) (t >>> 17);t = 1290239148;buf[150] = (byte) (t >>> 1);t = -574728849;buf[151] = (byte) (t >>> 4);t = -719005358;buf[152] = (byte) (t >>> 9);t = 1876915624;buf[153] = (byte) (t >>> 2);t = 1199807514;buf[154] = (byte) (t >>> 24);t = 1736086062;buf[155] = (byte) (t >>> 9);t = 1428665087;buf[156] = (byte) (t >>> 15);t = 1465062189;buf[157] = (byte) (t >>> 16);t = 1806504751;buf[158] = (byte) (t >>> 6);t = -1107893630;buf[159] = (byte) (t >>> 12);t = -1332882739;buf[160] = (byte) (t >>> 13);t = -812865465;buf[161] = (byte) (t >>> 7);t = -301937312;buf[162] = (byte) (t >>> 9);t = -2066697766;buf[163] = (byte) (t >>> 2);t = -1305493361;buf[164] = (byte) (t >>> 19);t = -1834581076;buf[165] = (byte) (t >>> 3);t = -737335093;buf[166] = (byte) (t >>> 10);t = 277137746;buf[167] = (byte) (t >>> 2);t = 1213819339;buf[168] = (byte) (t >>> 16);t = -2020418054;buf[169] = (byte) (t >>> 6);t = -1123641985;buf[170] = (byte) (t >>> 18);t = -431083209;buf[171] = (byte) (t >>> 13);t = 507128406;buf[172] = (byte) (t >>> 1);t = 1486767189;buf[173] = (byte) (t >>> 8);t = 1540719169;buf[174] = (byte) (t >>> 14);t = -223977405;buf[175] = (byte) (t >>> 12);t = 896301620;buf[176] = (byte) (t >>> 3);t = -435563115;buf[177] = (byte) (t >>> 13);t = -840788903;buf[178] = (byte) (t >>> 4);t = 768149722;buf[179] = (byte) (t >>> 13);t = 359679408;buf[180] = (byte) (t >>> 20);t = 312503117;buf[181] = (byte) (t >>> 3);t = -1499364026;buf[182] = (byte) (t >>> 11);t = 347282443;buf[183] = (byte) (t >>> 6);t = -1492879958;buf[184] = (byte) (t >>> 21);t = -231143130;buf[185] = (byte) (t >>> 16);t = -1009510186;buf[186] = (byte) (t >>> 6);t = -144302856;buf[187] = (byte) (t >>> 16);t = 206413772;buf[188] = (byte) (t >>> 10);t = 1295388250;buf[189] = (byte) (t >>> 15);t = 201556177;buf[190] = (byte) (t >>> 1);t = -1568103163;buf[191] = (byte) (t >>> 4);t = 711995476;buf[192] = (byte) (t >>> 23);t = -1020380039;buf[193] = (byte) (t >>> 20);t = -1865037191;buf[194] = (byte) (t >>> 10);t = 1160169965;buf[195] = (byte) (t >>> 9);t = 205920438;buf[196] = (byte) (t >>> 12);t = -1451120185;buf[197] = (byte) (t >>> 11);t = -1233229806;buf[198] = (byte) (t >>> 9);t = -550594739;buf[199] = (byte) (t >>> 4);t = -514344473;buf[200] = (byte) (t >>> 2);t = -2146228900;buf[201] = (byte) (t >>> 12);t = 1902766536;buf[202] = (byte) (t >>> 24);t = -1622775177;buf[203] = (byte) (t >>> 5);t = 1196522451;buf[204] = (byte) (t >>> 20);t = 1204497607;buf[205] = (byte) (t >>> 1);t = -771126874;buf[206] = (byte) (t >>> 2);t = -798885983;buf[207] = (byte) (t >>> 16);t = 377592311;buf[208] = (byte) (t >>> 22);t = -744708389;buf[209] = (byte) (t >>> 14);t = -1441356264;buf[210] = (byte) (t >>> 7);t = -232090605;buf[211] = (byte) (t >>> 9);t = 1079535253;buf[212] = (byte) (t >>> 1);t = 1370833305;buf[213] = (byte) (t >>> 24);t = -575092266;buf[214] = (byte) (t >>> 15);t = -1793356707;buf[215] = (byte) (t >>> 6);t = -2092531142;buf[216] = (byte) (t >>> 12);t = -539929596;buf[217] = (byte) (t >>> 6);t = -1862449155;buf[218] = (byte) (t >>> 10);t = 1506182314;buf[219] = (byte) (t >>> 1);t = 1411183225;buf[220] = (byte) (t >>> 20);t = -833367400;buf[221] = (byte) (t >>> 11);t = 1993118338;buf[222] = (byte) (t >>> 6);t = 1254343438;buf[223] = (byte) (t >>> 11);t = 2097333316;buf[224] = (byte) (t >>> 4);t = -1020599644;buf[225] = (byte) (t >>> 1);t = 1504837966;buf[226] = (byte) (t >>> 24);t = 1560637749;buf[227] = (byte) (t >>> 18);t = 2096285932;buf[228] = (byte) (t >>> 5);t = -1647656244;buf[229] = (byte) (t >>> 22);t = 819632956;buf[230] = (byte) (t >>> 17);t = -1838243791;buf[231] = (byte) (t >>> 19);t = 704859450;buf[232] = (byte) (t >>> 23);t = -155119545;buf[233] = (byte) (t >>> 10);t = -1243640035;buf[234] = (byte) (t >>> 18);t = 1723570069;buf[235] = (byte) (t >>> 15);t = -870163481;buf[236] = (byte) (t >>> 22);t = 1252841889;buf[237] = (byte) (t >>> 15);t = 599310583;buf[238] = (byte) (t >>> 23);t = 546156420;buf[239] = (byte) (t >>> 10);t = -1706602910;buf[240] = (byte) (t >>> 5);t = -1547751493;buf[241] = (byte) (t >>> 23);t = -1676911934;buf[242] = (byte) (t >>> 8);t = 726315834;buf[243] = (byte) (t >>> 23);t = 652793517;buf[244] = (byte) (t >>> 13);t = 1352635334;buf[245] = (byte) (t >>> 17);t = 2008250602;buf[246] = (byte) (t >>> 11);t = -359721084;buf[247] = (byte) (t >>> 21);t = 412988864;buf[248] = (byte) (t >>> 7);t = 24896652;buf[249] = (byte) (t >>> 4);t = 1381777616;buf[250] = (byte) (t >>> 19);t = 647377218;buf[251] = (byte) (t >>> 20);t = -1916909499;buf[252] = (byte) (t >>> 21);t = -516525273;buf[253] = (byte) (t >>> 18);t = -1190967479;buf[254] = (byte) (t >>> 11);t = -1004914964;buf[255] = (byte) (t >>> 8);t = -843129798;buf[256] = (byte) (t >>> 21);t = -2061884152;buf[257] = (byte) (t >>> 14);t = 996917533;buf[258] = (byte) (t >>> 11);t = -1647992822;buf[259] = (byte) (t >>> 12);t = -1248072206;buf[260] = (byte) (t >>> 5);t = -1338419663;buf[261] = (byte) (t >>> 6);t = 1627014593;buf[262] = (byte) (t >>> 2);t = -981452357;buf[263] = (byte) (t >>> 8);t = 1289462004;buf[264] = (byte) (t >>> 7);t = -132640563;buf[265] = (byte) (t >>> 1);t = -182001986;buf[266] = (byte) (t >>> 9);t = 78176047;buf[267] = (byte) (t >>> 20);t = -579830853;buf[268] = (byte) (t >>> 22);t = 607217809;buf[269] = (byte) (t >>> 8);t = -1678758817;buf[270] = (byte) (t >>> 22);t = 1757291309;buf[271] = (byte) (t >>> 18);t = -1780588556;buf[272] = (byte) (t >>> 23);t = 2017618667;buf[273] = (byte) (t >>> 1);t = 1384974727;buf[274] = (byte) (t >>> 5);t = -1788430066;buf[275] = (byte) (t >>> 7);t = -2108378523;buf[276] = (byte) (t >>> 1);t = 547545780;buf[277] = (byte) (t >>> 23);t = -775468351;buf[278] = (byte) (t >>> 8);t = 1783550400;buf[279] = (byte) (t >>> 9);t = 113124094;buf[280] = (byte) (t >>> 21);t = -1213642155;buf[281] = (byte) (t >>> 3);t = 2009201292;buf[282] = (byte) (t >>> 1);t = -2007931069;buf[283] = (byte) (t >>> 10);t = 1794502256;buf[284] = (byte) (t >>> 21);t = 214123336;buf[285] = (byte) (t >>> 22);t = 874883463;buf[286] = (byte) (t >>> 2);t = 177660975;buf[287] = (byte) (t >>> 19);t = 1187691800;buf[288] = (byte) (t >>> 24);t = -2097960859;buf[289] = (byte) (t >>> 11);t = -250464472;buf[290] = (byte) (t >>> 11);t = 1247686061;buf[291] = (byte) (t >>> 17);t = 1949906087;buf[292] = (byte) (t >>> 4);t = -456741512;buf[293] = (byte) (t >>> 9);t = -296518086;buf[294] = (byte) (t >>> 12);t = -155949447;buf[295] = (byte) (t >>> 12);t = -1253530778;buf[296] = (byte) (t >>> 3);t = 867747705;buf[297] = (byte) (t >>> 23);t = 60326377;buf[298] = (byte) (t >>> 14);t = -203892889;buf[299] = (byte) (t >>> 10);t = 1454558349;buf[300] = (byte) (t >>> 22);t = -844071245;buf[301] = (byte) (t >>> 22);t = -286469765;buf[302] = (byte) (t >>> 13);t = -733076005;buf[303] = (byte) (t >>> 16);t = -1144883411;buf[304] = (byte) (t >>> 4);t = -442649323;buf[305] = (byte) (t >>> 2);t = -1422576601;buf[306] = (byte) (t >>> 16);t = -1020501425;buf[307] = (byte) (t >>> 9);t = 160504584;buf[308] = (byte) (t >>> 3);t = 811069860;buf[309] = (byte) (t >>> 17);t = 1260721051;buf[310] = (byte) (t >>> 15);t = -969775407;buf[311] = (byte) (t >>> 20);t = 1303284147;buf[312] = (byte) (t >>> 21);t = -625032425;buf[313] = (byte) (t >>> 9);t = -97098121;buf[314] = (byte) (t >>> 4);t = -425649790;buf[315] = (byte) (t >>> 17);t = -1974847941;buf[316] = (byte) (t >>> 13);t = -741108166;buf[317] = (byte) (t >>> 14);t = -1753278184;buf[318] = (byte) (t >>> 2);t = -699103464;buf[319] = (byte) (t >>> 20);t = -2016955587;buf[320] = (byte) (t >>> 7);t = 315404156;buf[321] = (byte) (t >>> 17);t = -794832722;buf[322] = (byte) (t >>> 17);t = 356690031;buf[323] = (byte) (t >>> 1);t = 1038748936;buf[324] = (byte) (t >>> 2);t = -1700926048;buf[325] = (byte) (t >>> 17);t = -1127242610;buf[326] = (byte) (t >>> 23);t = -1992749651;buf[327] = (byte) (t >>> 21);t = -352680402;buf[328] = (byte) (t >>> 9);t = -1805635008;buf[329] = (byte) (t >>> 22);t = 563759584;buf[330] = (byte) (t >>> 15);t = -1361825188;buf[331] = (byte) (t >>> 3);t = -398229600;buf[332] = (byte) (t >>> 21);t = 277109317;buf[333] = (byte) (t >>> 8);t = -2125345654;buf[334] = (byte) (t >>> 6);t = -1755039026;buf[335] = (byte) (t >>> 20);t = 1387973774;buf[336] = (byte) (t >>> 20);t = 998598768;buf[337] = (byte) (t >>> 12);t = 865941091;buf[338] = (byte) (t >>> 8);t = 1817240253;buf[339] = (byte) (t >>> 21);t = -851319077;buf[340] = (byte) (t >>> 5);t = -1757625387;buf[341] = (byte) (t >>> 15);t = -1389827655;buf[342] = (byte) (t >>> 15);t = 2020976631;buf[343] = (byte) (t >>> 12);t = -585192751;buf[344] = (byte) (t >>> 1);t = -630679974;buf[345] = (byte) (t >>> 16);t = -1824603700;buf[346] = (byte) (t >>> 20);t = -1559211202;buf[347] = (byte) (t >>> 19);t = 796496100;buf[348] = (byte) (t >>> 11);t = -1683936451;buf[349] = (byte) (t >>> 10);t = 425432144;buf[350] = (byte) (t >>> 11);t = -1951725594;buf[351] = (byte) (t >>> 19);t = 1116926697;buf[352] = (byte) (t >>> 24);t = -587946101;buf[353] = (byte) (t >>> 7);t = -173581617;buf[354] = (byte) (t >>> 3);t = 929915210;buf[355] = (byte) (t >>> 2);t = 1414269247;buf[356] = (byte) (t >>> 16);t = 1314916010;buf[357] = (byte) (t >>> 21);t = 1111556037;buf[358] = (byte) (t >>> 19);t = 1260197527;buf[359] = (byte) (t >>> 21);t = -1860522194;buf[360] = (byte) (t >>> 18);t = 375823568;buf[361] = (byte) (t >>> 12);t = 1109235682;buf[362] = (byte) (t >>> 14);t = 139640494;buf[363] = (byte) (t >>> 14);t = -760216671;buf[364] = (byte) (t >>> 3);t = 222124937;buf[365] = (byte) (t >>> 6);t = 938188236;buf[366] = (byte) (t >>> 23);t = -2052563705;buf[367] = (byte) (t >>> 6);t = -2069157770;buf[368] = (byte) (t >>> 15);t = -677308299;buf[369] = (byte) (t >>> 6);t = -355951622;buf[370] = (byte) (t >>> 13);t = -1509849063;buf[371] = (byte) (t >>> 11);t = -854783137;buf[372] = (byte) (t >>> 14);t = 1423613063;buf[373] = (byte) (t >>> 17);t = 887322458;buf[374] = (byte) (t >>> 24);t = -77091213;buf[375] = (byte) (t >>> 19);t = -281955837;buf[376] = (byte) (t >>> 16);t = 485495047;buf[377] = (byte) (t >>> 23);t = -1834251829;buf[378] = (byte) (t >>> 17);t = 757682102;buf[379] = (byte) (t >>> 15);t = 607712685;buf[380] = (byte) (t >>> 9);t = -1883713311;buf[381] = (byte) (t >>> 2);t = -263312220;buf[382] = (byte) (t >>> 13);t = 1493888163;buf[383] = (byte) (t >>> 1);t = -1471944260;buf[384] = (byte) (t >>> 5);t = -2007877772;buf[385] = (byte) (t >>> 4);t = 47370827;buf[386] = (byte) (t >>> 3);t = -722958364;buf[387] = (byte) (t >>> 13);t = -365689838;buf[388] = (byte) (t >>> 4);t = -928366636;buf[389] = (byte) (t >>> 13);t = 1052541727;buf[390] = (byte) (t >>> 9);t = -1932584427;buf[391] = (byte) (t >>> 3);return new String(buf);}}.toString())

Private Key: MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCNAflaE0W7uuGLXh0wintiMC4puyZeXaMCO8OpRva0JtYW7q6qY+TY0o7pnyUIrKcoQpYbCiGX9CKFxmAxSLUD9FXlNtYA0ss6Msysa/GLhVWWMYg5Iuec9+8S4lNjACr4NV8U0QdaLSnz1x+CWE9Pat1rni3LapK5yJpmssklCrWE9BQDMnENFgAbCYxMPDDRgaSwZlUU6hOQcqKYyHqaHFmhen0B+gm6Gj/64uvYAmHkkVhbdpEW4X8lXsWWBvlnp82sTnVr4lyZqA9A0V5987sE3IgJDgoFna/5XpvrJBmGHdvYmu4E5hEuwdcWK8m2ei1VoPXibiXX1RHPypAzAgMBAAECggEAdbZuKMnp7twFqUi56WnRspgyEVhQoXpduGGX51p8XMwG8UHzwf5+bprn/xOB4QnwyWU81fnRLX76yt5eMwZVRqXUhvMOF8XhLgZ2YoICNMzsM+PJqpj+7UT06bjSj9T2ChrT8xbEon0NhqfRgAikvNGjYlG8PRIMxtc2PgGGdUqAiRR25LAILNzCRTRSvR848WAdQvA60nEugIND8/4LGMHTTKm/7/nIXetX0pI6JmrQMDuXknhGh1harUeGXARMS+Fgat/reeEkMHcYxFGRgY5lBQ6wilG5smuAVCU1NX2EIjSPalJwuX19jqUg/7XGsmMQxLFkDYxgd/fv9I0CUQKBgQD4yXvkZ60nKv+7S6e5FevVC0KkGYFEzeiN9MkWf38rAWUR6EuNp44irxoneaLhRp3d54grABIZJMRVQCRtxSM2BvNxReEArTQJjjr0bIBCwJMcRRiOBYYX19sJTSRtIvGWZmfaXmiB4obwDQxl6wR7aF9mOY6MV946mgl617MelQKBgQCRGIs2N/FMtIj9EYi82R0JWhOMULffcSDUsDIfQRjgPJ2Bu+k9acet2Hm85UN2jUoE3i6fBjZyzOaRAiT/hXLCNQVY8hddu7+2SIffnwwLPrO9MdPXTtizKvAXlX0K3G+r3MkZR/PDRV8DIL3bYgS3FzpUOgSm4aPyJXO7q6zppwKBgG5nI0axx4JZL5FTOoQFOVmanKEr/FSnN6s/VLlaLPnNradruZOMJqQ3plicPu7PoqDl7WR/rIhh64qVY1UfJcgE/6VlyDq/ohcXegwb1jNJOD9UXlgwFVihXr9a725LEoCWw0GBocj52L3QXI8h4yRMpgE8S4j2OVUyJEDSVdedAoGBAJCO0XPNPJ1daPYpWAA+l41PrxYm/WqifUEp4mX9J1mRSqOMog5Lq2Nqv68RA6vDjLFY4z4QpIKv3i8u4cmqHPGcfZ1mZR1ABvsHPEfxX8B8Ufr2/8YNihzHdLkqeJAvmxqxN7H2W8h6/vRQ1JcUCvqXK8fqnePd/scrxSh/HCEVAoGAU6TWO0/DOLHAISHNu8Yjf/EU/AP3xYfgHX7jq7T9/p16zj8pgePwPvPkLynyO0tNBtirOnVOzdxnkaKsCWxTKmnoNkcM6wvlrNh24/ZY3oeVhrruoqKwPYgqqIJEkMR7SR7YAUYv4EA6SdqQ85VpsTQlepHoIzGOY3dZHoFcLqU=
Certificate: PxoBxWvddp2rz0M+8CqniIJ22GZQ6Wzcqa3DgSySUzDMo83ZW95EeT5s6CVpnuSXsF5XTDVikQlS9JupBLOGe+bLkTaEunYSIHUNx4a+oZ6w8NCjJa5L+8UWi48AcVAmDpDWi3sOePStDOZaFbt8DucP0+iA0Nm0Entte5EJ1mmR38PhB3GYNGoAUPvnUDikm7iOHAdkDfePBukUVLPlQXfXTnmovCUsiZ1FO8pfqzfpwBeCfY9fWP3UYbjXLXgHgv/sc9jlBj9X2E3sNjWP9x380Eflfsc7o3Lh+aPvoeiD9VQWkVsTgX27w8ekU1wxJ1rG9ZMwOzXUDuttRnxj+w==

 */
// for more details refer TestCertificate.java
```

##### How to validate the certificate on each call
```java
// Initialize security context with certificate path
System.setProperty("cv.secureapp.certificate", <certificatePath>);
java -jar <parentJar> -Dcv.secureapp.certificate=<certificatePath>

/* Before using isCertificateValid method, initialize SecurityContext using SecurityContextBuilder
 * Note: initialize must be done only once 
 */
SecurityContextBuilder.withDefault()
                    .withCertificateFormat(new DelimitedCertificateFormatImpl())
                    .withPublicKey(OBFUSCATED_PUBLIC_KEY)
                    .initialize();

// call below stmt to validate certificate on each request
SecurityContext.isCertificateValid()

// For more details refer TestSecurityContext.java
```

##### Customizing Security Context
###### How to extend certificates to use json

```json5
// Example certificate json
{
    "Texp":"+Texp+", //Certificate expiry time
    "version":"1.23.4",
    "ntpserver":"time.org.demo"
}
```

<details><summary>Example of Custom Json Certificate Class </summary>
<p>

```java
/* 
  Example of Custom Json Certificate Class
 */
class JsonCertificateFormat implements CertificateFormat {

        private static final ObjectMapper objectMapper = new ObjectMapper();
        private Map<String, Object> mJson;
        private Map<String, Object> options;

        public JsonCertificateFormat(){
            options = new HashMap<>();
            options.put("secure-field", "secure-field");
        }

        @Override
        public Object getFieldData(String field) {
            validateCertificate();
            return mJson.getOrDefault(field, "field not found");
        }

        @Override
        public LocalDateTime getExpiryDate() {
            validateCertificate();
            return LocalDateTime.parse(String.valueOf(getFieldData(String.valueOf(options.get("secure-field")))));
        }

        @Override
        public CertificateFormat set(String name, Object value) {
            options.put(name, value);
            return this;
        }

        @Override
        public CertificateFormat fromData(Object certificateContent) {
            try {
                mJson = objectMapper.readValue(String.valueOf(certificateContent), Map.class);
            } catch (IOException e) {
                e.printStackTrace();
            }
            return this;
        }

        private void validateCertificate(){
            if(mJson == null || mJson.size() == 0)
                throw new AssertionError("Certificate is absent, kindly use `fromData` method to push certificate");
        }
    }
    
/* 
   How to use Custom Certificate implementation
 */
    @Test
    public void testWithCustomCertificateFormat(){

        LocalDateTime Texp = LocalDateTime.now().plusMinutes(1);
        String rawdata = "{\"Texp\":\""+Texp+"\",\"version\":\"1.23.4\",\"ntpserver\":\"time.org.demo\"}";

        String certificateContent = null;
        try {
            certificateContent = CertificateUtil.encrypt(rawdata, PRIVATE_KEY);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String certificatePath = createTempCertificate(certificateContent);
        System.setProperty("cv.secureapp.certificate", certificatePath);
        SecurityContextBuilder.withDefault()
                .withCertificateFormat(new JsonCertificateFormat().set("secure-field", "Texp"))
                .withPublicKey(PUBLIC_KEY)
                .initialize();
        SecurityContext.isCertificateValid();

        /* It must throw java.lang.RuntimeException: Certificate Expired on  */
        SecurityContext.isCertificateValid();
    }

// For details refer TestJsonCertificateFormat        
```
</p>
</details>

###### How to use instance / machine time instead of Network Time Protocol to validate certificate
```java
/* 
  SecurityContext default behaviour is rely on NTP server, but it can be change to use 
  instance time
 */
 SecurityContextBuilder.withDefault()
                     .withCertificateFormat(new DelimitedCertificateFormatImpl())
                     .withPublicKey(OBFUSCATED_PUBLIC_KEY)
                     .useInstanceTime() // to use instance time instead of NTP server
                     .initialize();
 SecurityContext.isCertificateValid();

```
###### Override default system variable to refer certificate path 
Jar search for certificate path using _**cv.secureapp.certificate**_ system variable, we can override using _**useCertificateVariableName**_
```java
Default 
System.setProperty("cv.secureapp.certificate", certificatePath);

Custom
System.setProperty("custom_path", certificatePath);
SecurityContextBuilder.withDefault()
                    .useCertificateVariableName("custom_path_test")
                    .withPublicKey(OBFUSCATED_PUBLIC_KEY)
                    .withCertificateFormat(new DelimitedCertificateFormatImpl())
                    .initialize();
```

###### Public Key obfuscation
We used proguard to obfuscate the jar, the glitch with proguard is it wont obfuscate resource files 
or String variable in class. The essence of security is getting comprised if public key within code is 
visible after obfuscation, to hide the public key we encourage to implement your own obfuscation code.
We do provide a way to build obfuscated version of public key
```java
    @Test
    public void basicWorking(){
        String originalString = "You important data stuffs";
        String obfuscatedCode = Obfuscator.getObfuscatedCode(originalString);
        System.out.println("String data in obfuscated code --> "+obfuscatedCode);
        System.out.println("The Original String --> "+(new Object() {int t;public String toString() {byte[] buf = new byte[25];t = 1798417526;buf[0] = (byte) (t >>> 21);t = -1469090647;buf[1] = (byte) (t >>> 16);t = 647452009;buf[2] = (byte) (t >>> 12);t = 1305598083;buf[3] = (byte) (t >>> 2);t = 1887902320;buf[4] = (byte) (t >>> 6);t = 2092346784;buf[5] = (byte) (t >>> 15);t = 461827047;buf[6] = (byte) (t >>> 19);t = -893923851;buf[7] = (byte) (t >>> 15);t = 1036931249;buf[8] = (byte) (t >>> 13);t = 1679626480;buf[9] = (byte) (t >>> 14);t = -793421756;buf[10] = (byte) (t >>> 6);t = -1516605780;buf[11] = (byte) (t >>> 8);t = -1794732407;buf[12] = (byte) (t >>> 5);t = -1810751407;buf[13] = (byte) (t >>> 8);t = -1504918460;buf[14] = (byte) (t >>> 20);t = -983341539;buf[15] = (byte) (t >>> 4);t = 1956087314;buf[16] = (byte) (t >>> 24);t = 1573347680;buf[17] = (byte) (t >>> 8);t = 1208807218;buf[18] = (byte) (t >>> 22);t = -2140243865;buf[19] = (byte) (t >>> 13);t = 2126139430;buf[20] = (byte) (t >>> 15);t = -581337316;buf[21] = (byte) (t >>> 22);t = 1715615834;buf[22] = (byte) (t >>> 24);t = -1285320308;buf[23] = (byte) (t >>> 23);t = 1936102500;buf[24] = (byte) (t >>> 24);return new String(buf);}}.toString()));
    }
    
    /*
     String data in obfuscated code --> (new Object() {int t;public String toString() {byte[] buf = new byte[25];t = 544037291;buf[0] = (byte) (t >>> 8);t = -1492255078;buf[1] = (byte) (t >>> 13);t = 1035660100;buf[2] = (byte) (t >>> 9);t = 979510289;buf[3] = (byte) (t >>> 5);t = -1587065563;buf[4] = (byte) (t >>> 5);t = -1932077381;buf[5] = (byte) (t >>> 12);t = 1887213456;buf[6] = (byte) (t >>> 24);t = 425539581;buf[7] = (byte) (t >>> 7);t = 1746114169;buf[8] = (byte) (t >>> 11);t = 776343186;buf[9] = (byte) (t >>> 5);t = 555320928;buf[10] = (byte) (t >>> 10);t = 1189798338;buf[11] = (byte) (t >>> 20);t = 1824349441;buf[12] = (byte) (t >>> 6);t = -1006207214;buf[13] = (byte) (t >>> 21);t = -2103183671;buf[14] = (byte) (t >>> 1);t = -1800354562;buf[15] = (byte) (t >>> 15);t = 1525180781;buf[16] = (byte) (t >>> 17);t = 1052998309;buf[17] = (byte) (t >>> 17);t = 1825113591;buf[18] = (byte) (t >>> 11);t = -1612388412;buf[19] = (byte) (t >>> 9);t = 1385444585;buf[20] = (byte) (t >>> 1);t = -1982347482;buf[21] = (byte) (t >>> 18);t = 1783617958;buf[22] = (byte) (t >>> 6);t = -1449555877;buf[23] = (byte) (t >>> 18);t = -849858955;buf[24] = (byte) (t >>> 5);return new String(buf);}}.toString())
     
     The Original String --> You important data stuffs
     */
    
```

##### Future enhancement
Code obfuscate make reverse engineering hard, can we use obfuscation with encryption to make sharing jar more secure and nearly impossible to reverse engineer 

