# Device authorization

### Use with [Ion auth](https://github.com/benedmunds/CodeIgniter-Ion-Auth "Ion auth") 
Match and ip and user agent controlling devices authorized to login

## How to use
#### Install and configure Ion Auth correctly
#### Copy the files from the respective folders and paste in the project

O `$config['use_ci_email'] = TRUE;` must be set to `TRUE` and configured correctly

Add to your [database](https://github.com/matheuscastroweb/device-authorization/blob/master/sql/device_authorization.sql "database") 

[Loading model](https://codeigniter.com/user_guide/general/models.html "Loading model") with functions 
```php
$this->load->model('device_authorization');
```

Add hook with [set_hook()](http://benedmunds.com/ion_auth/#set_hook "set_hook()") before function login 
```php
$this->ion_auth->set_hook(
	'post_login', 
	'verify_device_authorization', 
	$this->device_authorization, 
	$this->device_authorization->verify_device($this->input->post('identity')), 
	$this->input->post('identity')
	);
```


Add to your controller Auth to receive email confirmations
```php
/**
* Device authorization -  match in ip and user agent
*
* @param string | null $code The reset code
*/
public function device_authorization($code = NULL)
 {
    if (!$code) {
            show_404();
     }
     $this->load->model('device_authorization');
     $authorization = $this->device_authorization->device_authorization($code);

     // If the code is valid then display the password reset form
     if ($authorization) {
         $this->session->set_flashdata('message', $this->ion_auth->messages());
         redirect('auth/login', 'refresh');
     } else {
       // If the code is invalid then send them back to the login page
      $this->session->set_flashdata('message', $this->ion_auth->errors());
      redirect('auth/login', 'refresh');
     }
 }
```
