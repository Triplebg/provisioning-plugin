package marvell.provisioning;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;

import android.os.Handler;
import android.os.Message;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import android.os.Build;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * This class echoes a string called from JavaScript.
 */
public class MarvellProvisioning extends CordovaPlugin {

	private CallbackContext context;
	
	Boolean xmitStarted = false;

    xmitterTask xmitter;

	Boolean inProgress = false;

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("SendProvisionData")) 
		{
			if(inProgress)
			{
				callbackContext.error("InProgress");
				return true;
			}
			
            String ssid = args.getString(0);
            String pss = args.getString(1); 
			String key = args.getString(2);
			String data = args.getString(3);
			
			context = callbackContext;
			inProgress = true;
			
			this.SendMulticast(ssid,pss,key,data);
            return true;
        }
		else if(action.equals("GetCurrentSSID"))
		{
			this.GetCurrentSSID(callbackContext);
			return true;
		}
        return false;
    }

    private void SendMulticast(String SSID,String pass, String key, String data)
    {
        try {
            if (xmitStarted == false) {


                xmitter = new xmitterTask();
                xmitter.handler = handler;

                xmitStarted = true;

                CRC32 crc32 = new CRC32();
                crc32.reset();
                crc32.update(pass.getBytes());
                xmitter.passCRC = (int) crc32.getValue() & 0xffffffff;
                Log.d("MRVL", Integer.toHexString(xmitter.passCRC));

                xmitter.ssid = SSID;
                xmitter.ssidLen = SSID.length();

                xmitter.customDataLen = data.length() / 2;

                if (xmitter.customDataLen % 16 == 0)
                {
                    xmitter.cipherDataLen = xmitter.customDataLen;
                }
                else
                {
                    xmitter.cipherDataLen = ((xmitter.customDataLen / 16) + 1) * 16;
                }

                xmitter.customData = hexStringToByteArray(data, xmitter.cipherDataLen);

                CRC32 crc32_customdata = new CRC32();
                crc32_customdata.reset();
                crc32_customdata.update(xmitter.customData);
                xmitter.customDataCRC = (int) crc32_customdata.getValue() & 0xffffffff;
                Log.d("MRVL", "CRC is " + Integer.toHexString((xmitter.customDataCRC)));
                Log.d("MRVL", "Length is " + xmitter.customData.length);

//                int deviceVersion = Build.VERSION.SDK_INT;
//
//                if (deviceVersion >= 17) {
//                    if (xmitter.ssid.startsWith("\"") && xmitter.ssid.endsWith("\"")) {
//                        xmitter.ssidLen = wifiMgr.getConnectionInfo().getSSID().length() - 2;
//                        xmitter.ssid = xmitter.ssid.substring(1, xmitter.ssid.length() - 1);
//                    }
//                }

                Log.d("MRVL", "SSID LENGTH IS " + xmitter.ssidLen);
                CRC32 crc32_ssid = new CRC32();
                crc32_ssid.reset();
                crc32_ssid.update(xmitter.ssid.getBytes());
                xmitter.ssidCRC = (int) crc32_ssid.getValue() & 0xffffffff;

                if (key.length() != 0)
                {
                    if (pass.length() % 16 == 0)
                    {
                        xmitter.passLen = pass.length();
                    }
                    else
                    {
                        xmitter.passLen = (16 - (pass.length() % 16)) + pass.length();
                    }

                    byte[] plainPass = new byte[xmitter.passLen];

                    for (int i = 0; i < pass.length(); i++)
                        plainPass[i] = pass.getBytes()[i];

                    xmitter.passphrase = myEncryptPassphrase(key, plainPass, xmitter.ssid);
                    xmitter.cipherData = myEncryptCustomData(key, xmitter.customData, xmitter.ssid);
                    Log.d("MRVL", "AmeyRocks" + xmitter.cipherDataLen + " " + xmitter.cipherData.length);
                }
                else
                {
                    xmitter.passphrase = pass.getBytes();
                    xmitter.passLen = pass.length();
                }

                xmitter.mac = new char[6];
                xmitter.preamble = new char[6];
                //String[] macParts = wifiInf.getBSSID().split(":");

                xmitter.preamble[0] = 0x45;
                xmitter.preamble[1] = 0x5a;
                xmitter.preamble[2] = 0x50;
                xmitter.preamble[3] = 0x52;
                xmitter.preamble[4] = 0x32;
                xmitter.preamble[5] = 0x32;

//                Log.d("MRVL", wifiInf.getBSSID());
//                for (int i = 0; i < 6; i++)
//                    xmitter.mac[i] = (char) Integer.parseInt(macParts[i], 16);
                xmitter.resetStateMachine();
                xmitter.execute("");
            } else {
                xmitStarted = false;
                xmitter.cancel(true);
            }
        } catch (Error err) {
            Log.e("MRVL", err.toString());
        }
    }

	final Handler handler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            if (msg.what == 42) {
                Log.d("MRVL", "ADI ASync task exited");
                xmitStarted = false;
				inProgress = false;
				context.success();
				context = null;
				//MessageBoard.setText("Please check indicators on the device.\n The device should have been provisioned.\n If not, please retry.");
            } else if (msg.what == 43) {
                //MessageBoard.setText("Information sent " + msg.arg1 / 2 + " times.");
            }
            super.handleMessage(msg);
        }
    };

    private class xmitterTask extends AsyncTask<String, Void, String> {
        byte[] passphrase;
        byte[] customData;
        byte[] cipherData;
        String ssid;
        char[] mac;
        char[] preamble;
        int passLen;
        int ssidLen;
        int customDataLen;
        int cipherDataLen;
        int passCRC;
        int ssidCRC;
        int customDataCRC;
        Handler handler;

        private int state, substate;

        public void resetStateMachine() {
            state = 0;
            substate = 0;
        }

        private void xmitRaw(int u, int m, int l) {
            MulticastSocket ms;
            InetAddress sessAddr;
            DatagramPacket dp;

            byte[] data = new byte[2];
            data = "a".getBytes();

            u = u & 0x7f; /* multicast's uppermost byte has only 7 chr */

            try {
//				Log.d("MRVL", "239." + u + "." + m + "." + l);
                sessAddr = InetAddress
                        .getByName("239." + u + "." + m + "." + l);
                ms = new MulticastSocket(1234);
                dp = new DatagramPacket(data, data.length, sessAddr, 5500);
                ms.send(dp);
                ms.close();
            } catch (UnknownHostException e) {
                // TODO Auto-generated catch block
                // e.printStackTrace();
                Log.e("MRVL", "Exiting 5");
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        private void xmitState0(int substate) {
            int i, j, k;

            // Frame-type for preamble is 0b11110<substate1><substate0>
            // i = <frame-type> | <substate> i.e. 0x78 | substate
            k = preamble[2 * substate];
            j = preamble[2 * substate + 1];
            i = substate | 0x78;

            xmitRaw(i, j, k);
        }

        private void xmitState1(int substate, int len) {
            // Frame-type for SSID is 0b10<5 substate bits>
            // u = <frame-type> | <substate> i.e. 0x40 | substate
            if (substate == 0) {
                int u = 0x40;
                xmitRaw(u, ssidLen, ssidLen);
            } else if (substate == 1 || substate == 2) {
                int k = (int) (ssidCRC >> ((2 * (substate - 1) + 0) * 8)) & 0xff;
                int j = (int) (ssidCRC >> ((2 * (substate - 1) + 1) * 8)) & 0xff;
                int i = substate | 0x40;
                xmitRaw(i, j, k);
            } else {
                int u = 0x40 | substate;
                int l = (0xff & ssid.getBytes()[(2 * (substate - 3))]);
                int m;
                if (len == 2)
                    m = (0xff & ssid.getBytes()[(2 * (substate - 3)) + 1]);
                else
                    m = 0;
                xmitRaw(u, m, l);
            }
        }

        private void xmitState2(int substate, int len) {
            // Frame-type for Passphrase is 0b0<6 substate bits>
            // u = <frame-type> | <substate> i.e. 0x00 | substate
            if (substate == 0) {
                int u = 0x00;
                xmitRaw(u, passLen, passLen);
            } else if (substate == 1 || substate == 2) {
                int k = (int) (passCRC >> ((2 * (substate - 1) + 0) * 8)) & 0xff;
                int j = (int) (passCRC >> ((2 * (substate - 1) + 1) * 8)) & 0xff;
                int i = substate;
                xmitRaw(i, j, k);
            } else {
                int u = substate;
                int l = (0xff & passphrase[(2 * (substate - 3))]);
                int m;
                if (len == 2)
                    m = (0xff & passphrase[(2 * (substate - 3)) + 1]);
                else
                    m = 0;
                xmitRaw(u, m, l);
            }
        }

        private void xmitState3(int substate, int len) {
            if (substate == 0) {
                int u = 0x60;
                xmitRaw(u, customDataLen, customDataLen);
            } else if (substate == 1 || substate == 2) {
                int k = (int) (customDataCRC >> ((2 * (substate - 1) + 0) * 8)) & 0xff;
                int j = (int) (customDataCRC >> ((2 * (substate - 1) + 1) * 8)) & 0xff;
                int i = substate | 0x60;
                xmitRaw(i, j, k);
            } else {
                int u = 0x60 | substate;
                int l = (0xff & cipherData[(2 * (substate - 3))]);
                int m;
                if (len == 2)
                    m = (0xff & cipherData[(2 * (substate - 3)) + 1]);
                else
                    m = 0;
                xmitRaw(u, m, l);
            }
        }

        private void stateMachine() {
            switch (state) {
                case 0:
                    if (substate == 3) {
                        state = 1;
                        substate = 0;
                    } else {
                        xmitState0(substate);
                        substate++;
                    }
                    break;
                case 1:
                    xmitState1(substate, 2);
                    substate++;
                    if (ssidLen % 2 == 1) {
                        if (substate * 2 == ssidLen + 5) {
                            xmitState1(substate, 1);
                            state = 2;
                            substate = 0;
                        }
                    } else {
                        if ((substate - 1) * 2 == (ssidLen + 4)) {
                            state = 2;
                            substate = 0;
                        }
                    }
                    break;
                case 2:
                    xmitState2(substate, 2);
                    substate++;
                    if (passLen % 2 == 1) {
                        if (substate * 2 == passLen + 5) {
                            xmitState2(substate, 1);
                            state = 3;
                            substate = 0;
                        }
                    } else {
                        if ((substate - 1) * 2 == (passLen + 4)) {
                            state = 3;
                            substate = 0;
                        }
                    }
                    break;
                case 3:
                    xmitState3(substate, 2);
                    substate++;
                    if (cipherDataLen % 2 == 1) {
                        if (substate * 2 == cipherDataLen + 5) {
                            xmitState3(substate, 1);
                            state = 0;
                            substate = 0;
                        }
                    } else {
                        if ((substate - 1) * 2 == cipherDataLen + 4) {
                            state = 0;
                            substate = 0;
                        }
                    }
                    break;
                default:
                    Log.e("MRVL", "I shouldn't be here");
            }
        }

        protected String doInBackground(String... params) {
            WifiManager wm = (WifiManager) cordova.getActivity().getSystemService(Context.WIFI_SERVICE);
            WifiManager.MulticastLock mcastLock = wm.createMulticastLock("mcastlock");
            mcastLock.acquire();

            int i = 0;

            while (true) {
                if (state == 0 && substate == 0)
                    i++;

                if (i % 5 == 0) {
                    Message msg = handler.obtainMessage();
                    msg.what = 43;
                    msg.arg1 = i;
                    handler.sendMessage(msg);
                }

				/* Stop trying after doing 50 iterations. Let user retry. */
                if (i >= 600)
                    break;

                if (isCancelled())
                    break;

                stateMachine();

//				try {
//					Thread.sleep(10);
//				} catch (InterruptedException e) {
                // TODO Auto-generated catch block
                // e.printStackTrace();
//					break;
//				}
            }

            mcastLock.release();

            if (i >= 50) {
                Message msg = handler.obtainMessage();
                msg.what = 42;
                handler.sendMessage(msg);
            }
            return null;
        }


        @Override
        protected void onPostExecute(String result) {
        }

        @Override
        protected void onPreExecute() {
        }

        @Override
        protected void onProgressUpdate(Void... values) {
        }
    }

	
	
    private static byte[] hexStringToByteArray(String s, int blockLen)
    {
        int len = s.length();
        byte[] data = new byte[blockLen];
        Arrays.fill(data, (byte)0);
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        Log.d("MRVL", data.toString());
        return data;
    }

    public static byte[] myEncryptCustomData(String key, byte[] plainText, String ssid) {

        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++)
            iv[i] = 0;

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher;
        byte[] encrypted = null;
        try {
            int iterationCount = 4096;
            int keyLength = 256;
            //int saltLength = keyLength / 8;
            byte salt[] = ssid.getBytes();

            Log.d("MRVL", "key salt itercount " + key + " " + ssid + " " + iterationCount);
            KeySpec keySpec = new PBEKeySpec(key.toCharArray(), salt, iterationCount, keyLength);

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
            SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");

            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
            encrypted = cipher.doFinal(plainText);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return encrypted;
    }

    public static byte[] myEncryptPassphrase(String key, byte[] plainText, String ssid) {

        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++)
            iv[i] = 0;

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher;
        byte[] encrypted = null;
        try {
            int iterationCount = 4096;
            int keyLength = 256;
            //int saltLength = keyLength / 8;
            byte salt[] = ssid.getBytes();

            Log.d("MRVL", "key salt itercount " + key + " " + ssid + " " + iterationCount);
            KeySpec keySpec = new PBEKeySpec(key.toCharArray(), salt, iterationCount, keyLength);

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
            SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");

            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
            encrypted = cipher.doFinal(plainText);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return encrypted;
    }

	private void GetCurrentSSID(CallbackContext callbackContext)
	{
		WifiManager wifiMgr = (WifiManager) cordova.getActivity().getSystemService(Context.WIFI_SERVICE);
		String ssid = wifiMgr.getConnectionInfo().getSSID();
		
		int deviceVersion = Build.VERSION.SDK_INT;

		if (deviceVersion >= 17) 
		{
			if (ssid.startsWith("\"") && ssid.endsWith("\"")) 
			{
				ssid = ssid.substring(1, ssid.length() - 1);
			}
		}
		
		
		callbackContext.success(ssid);
	}
	
	
	
}
