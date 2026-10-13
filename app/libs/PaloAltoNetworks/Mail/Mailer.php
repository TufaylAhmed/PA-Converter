<?php
/**
 * Created by PhpStorm.
 * User: didacgil
 * Date: 8/3/16
 * Time: 16:03
 */
namespace PaloAltoNetworks\Mail;

class Mailer
{
    protected $mailer;

    protected $view;

    public function __construct($view, $mailer)
    {
        $this->view = $view;
        $this->mailer = $mailer;
    }

    public function send($template, $data, $callback)
    {
        $message = new Message($this->mailer);

        $this->view->appendData($data);

        $message->body($this->view->render($template));
        $this->mailer->msgHTML($this->view->render($template), dirname(__FILE__));

        call_user_func($callback, $message);

        $this->mailer->send();
    }
}