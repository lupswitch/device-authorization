<?php

defined('BASEPATH') or exit('No direct script access allowed');

class Device_authorization extends Ion_auth_model
{
    /**
     * Database object
     *
     * @var object
     */
    protected $db;

    public function __construct()
    {
        // By default, use CI's db that should be already loaded
        $CI = &get_instance();
        $this->db = $CI->db;
        $this->config->load('ion_auth', TRUE);
    }

    public function __get($var)
    {
        return get_instance()->$var;
    }

    /**
     * Getter to the DB connection used by Ion Auth
     * May prove useful for debugging
     *
     * @return object
     */
    public function db()
    {
        return $this->db;
    }

    public function verify_device($identity)
    {

        print_r($query->row());
        exit();
        if ($this->verify_authorization($identity) == FALSE) {

            $this->increase_device_authorization($identity);

            $this->ion_auth->set_error('device_confirmation_sent');

            return FALSE;
            exit();
        } else {
            $row = $this->verify_authorization($identity);

            if (is_numeric($row->active) && $row->active != 1) {

                //$this->ion_auth->logout();
                $this->ion_auth->set_error('login_unsuccessful_not_allowed');
                return FALSE;
                exit();
            } else {
                $this->ion_auth->set_message('login_successful');
                return TRUE;
            }
        }
    }


    /**
     * Verify if device is allowed
     *
     * @param    string $identity
     *
     * @return    bool|array
     * @author    Matheus
     * 
     */
    public function verify_authorization($identity)
    {
        if (empty($identity)) {
            return FALSE;
        }

        $this->load->library('user_agent');

        $user_agent = $this->agent->browser() . ' on ' . $this->agent->platform();
        $ip_address = $this->input->ip_address();

        $query = $this->db->select('*')
            ->where('login', $identity)
            ->where('user_agent', $user_agent)
            ->where('ip_address', $ip_address)
            ->limit(1)
            ->get('device_authorization');

        return $query->row() ?: FALSE;
    }



    /**
     * Request a device authorization
     *
     * @param  string $identity
     *
     * @return bool|string
     * @author Matheus
     * 
     */
    public function increase_device_authorization($identity)
    {
        if (empty($identity)) {
            return FALSE;
        }

        $this->load->library('user_agent');

        // Generate random token: smaller size because it will be in the URL
        $token = $this->ion_auth_model->_generate_selector_validator_couple(20, 80);


        $data = [
            'user_agent'         => $this->agent->browser() . ' on ' . $this->agent->platform(),
            'ip_address'         => $this->input->ip_address(),
            'allowed_selector'     => $token->selector,
            'allowed_code'         => $token->validator_hashed,
            'login'             => strtolower($identity),
        ];

        $this->db->insert('device_authorization', $data);

        if ($this->db->affected_rows() === 1) {

            $user = $this->get_user_by_code_device_authorization($token->user_code);

            $data = [
                'user_agent' => $this->agent->browser() . ' on ' . $this->agent->platform(),
                'ip_address' => $this->input->ip_address(),
                'code'       => $token->user_code,
                'identity'   => $user->first_name,
                'time'       => time()
            ];

            if (!$this->config->item('use_ci_email', 'ion_auth')) {
                return $data;
            } else {

                $message = $this->load->view($this->config->item('email_templates', 'ion_auth') . 'device_authorization.tpl.php', $data, TRUE);
                $this->email->clear();
                $this->email->from($this->config->item('admin_email', 'ion_auth'), $this->config->item('site_title', 'ion_auth'));

                $this->email->to($user->email);
                $this->email->subject($this->config->item('site_title', 'ion_auth') . ' - Please verify your device');
                $this->email->message($message);

                if ($this->email->send()) {
                    $this->ion_auth->set_message('device_authorization_sent_with_email');
                    return TRUE;
                }

                $this->ion_auth->set_error('device_authorization_not_sent_with_email');
                return FALSE;
            }
        } else {

            $this->ion_auth->set_error('device_authorization_not_affected_rows');
            return FALSE;
        }
    }

    /**
     * Receives the device authorization request
     *
     * @param  int|string $code 
     *
     * @return bool
     * @author Matheus
     */
    public function device_authorization($code = FALSE)
    {
        if ($code === FALSE) {
            return FALSE;
        }

        $device_id = $this->activate_device_authorization($code);

        if ($device_id) {

            $data = [
                'allowed_selector' => NULL,
                'allowed_code'     => NULL,
                'active'           => 1
            ];

            $this->db->update('device_authorization', $data, ['id' => $device_id]);

            if ($this->db->affected_rows() === 1) {
                $this->ion_auth->set_message('authorized_device');
                return TRUE;
            }
        }
        $this->ion_auth->set_error('unauthorized_device');
        return FALSE;
    }

    /**
     * Authorize device via email
     *
     * @param   string $code
     *
     * @return  bool|int
     * @author  Matheus
     */
    public function activate_device_authorization($code)
    {
        // Retrieve the token object from the code
        $token = $this->ion_auth_model->_retrieve_selector_validator_couple($code);

        if ($token) {
            // Get device to this selector code
            $query = $this->db->select('id, allowed_selector, allowed_code')
                ->where('allowed_selector', $token->selector)
                ->get('device_authorization');

            $device = $query->row();

            if ($device) {
                // Check the hash against the validator
                if ($this->ion_auth_model->verify_password($token->validator, $device->allowed_code)) {
                    return $device->id;
                }
            }
        }

        return FALSE;
    }


    /**
     * Get user information with the code sent
     *
     * @param bool $code
     *
     * @return     bool|array
     * @author     Matheus
     */
    public function get_user_by_code_device_authorization($code)
    {

        // Retrieve the token object from the code
        $token = $this->ion_auth_model->_retrieve_selector_validator_couple($code);

        if ($token) {
            // Retrieve the user according to this selector
            $query = $this->db->select('allowed_selector, allowed_code, login')
                ->where('allowed_selector', $token->selector)
                ->get('device_authorization');

            $allowed = $query->row();

            if ($allowed) {
                // Check the hash against the validator
                if ($this->ion_auth->verify_password($token->validator, $allowed->allowed_code)) {
                    $query = $this->db->select('*')
                        ->where('email', $allowed->login)
                        ->get('users');

                    return $query->row();
                }
            }
        }

        return FALSE;
    }
}
