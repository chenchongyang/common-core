package cn.chenchongyang.core;

import cn.chenchongyang.core.crypto.SysCryptUtil;

public class App {
    public static void main(String[] args) {

        SysCryptUtil.initWorkKeyAndVerifyDigest();


        String asdas = SysCryptUtil.encrypt("asdqweqwecCCCASD643564cc陈崇洋as");
        System.out.println(SysCryptUtil.decrypt(asdas));
    }
}
