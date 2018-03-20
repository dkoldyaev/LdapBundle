<?php
/*
 * This file is part of the Symfony framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace IMAG\LdapBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\SecurityContext;

class DefaultController extends Controller
{
	public function loginAction()
	{
		$error = $this->getAuthenticationError();

		$session = $this->getRequest()->getSession();
		return $this->render('IMAGLdapBundle:Default:login.html.twig',
			array(
			     'last_username' => $this->get('request')->getSession()->get(SecurityContext::LAST_USERNAME),
			     'error' => $error,
			     'token' => $this->generateToken(),
			     '_target_path' => $session->get('_security.restricted_area.target_path')
			));
	}

	private function getAuthenticationError()
	{
		if ($this->get('request')->attributes->has(SecurityContext::AUTHENTICATION_ERROR)) {
			return $this->get('request')->attributes->get(SecurityContext::AUTHENTICATION_ERROR);
		}

		return $this->get('request')->getSession()->get(SecurityContext::AUTHENTICATION_ERROR);
	}

	private function generateToken()
	{
		$token = $this->get('form.csrf_provider')
			->generateCsrfToken('ldap_authenticate');

		return $token;
	}
}
