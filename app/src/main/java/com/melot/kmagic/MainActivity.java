package com.melot.kmagic;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;


import com.melot.magic.Magic;

public class MainActivity extends Activity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("magic");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            // Example of a call to a native method
            TextView tv = findViewById(R.id.sample_text);
           // tv.setText(Magic.fire("hello"));
            tv.setText(Magic.enp("u=10000975&p=+123456"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}
