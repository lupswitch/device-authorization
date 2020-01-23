<html>

<body>
    <h1>Hey, <?php echo $identity ?></h1>

    <p>A sign in attempt requires further verification because we did not recognize your device.</p>

    <p>Device: <?php echo $user_agent ?></p>
    <p>Ip Address: <?php echo $ip_address ?></p>
    <p>Time: <?php echo gmdate('d-m-Y  H:i', $time) ?></p>

    <p><?php echo anchor('auth/device_authorization/' . $code, 'Click here'); ?> to authorize this device</p>

</body>

</html>