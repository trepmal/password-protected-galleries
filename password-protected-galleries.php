<?php
/*
 * Plugin Name: Password Protected Galleries
 * Plugin URI: trepmal.com
 * Description: Add password protection to galleries
 * Version:
 * Author: Kailey Lampert
 * Author URI: kaileylampert.com
 * License: GPLv2 or later
 * TextDomain: ppg
 * DomainPath:
 * Network:
 */


/**
 * Whether gallery requires password and correct password has been provided.
 *
 * @param array $password Gallery password. Ideally, galleries would have unique ids that we could use, but using the password will work.
 * @return bool false if a password is not required or the correct password cookie is present, true otherwise.
 */
function gallery_password_required( $password ) {

	if ( empty( $password ) )
		return false;

	if ( ! isset( $_COOKIE['wp-postpass_' . COOKIEHASH] ) )
		return true;

	require_once ABSPATH . 'wp-includes/class-phpass.php';
	$hasher = new PasswordHash( 8, true );

	$hash = wp_unslash( $_COOKIE[ 'wp-postpass_' . COOKIEHASH ] );
	if ( 0 !== strpos( $hash, '$P$B' ) )
		return true;

	return ! $hasher->CheckPassword( $password, $hash );
}

/**
 * Retrieve protected gallery password form content.
 *
 * @since 1.0.0
 * @uses apply_filters() Calls 'the_password_form' filter on output.
 * @param int $gallery_id Gallery ID
 * @return string HTML content for password form for password protected post.
 */
function ppg_get_the_password_form( $gallery_id = 'test' ) {
	$label = 'pwbox-' . ( empty($gallery_id) ? rand() : $gallery_id );
	$output = '<form action="' . esc_url( site_url( 'wp-login.php?action=postpass', 'login_post' ) ) . '" class="post-password-form" method="post">
	<!--<p>' . __( 'This content is password protected. To view it please enter your password below:' ) . '</p>-->
	<p><label for="' . $label . '">' . __( 'Password:' ) . ' <input name="post_password" id="' . $label . '" type="password" size="20" /></label> <input type="submit" name="Submit" value="' . esc_attr__( 'Submit' ) . '" /></p>
	</form>
	';
	return apply_filters( 'the_password_form', $output );
}


/**
 * Filter gallery output. If has password and it hasn't been provided, show form. Else, show gallery.
 *
 * @param string $default
 * @param string $attr Gallery attributes
 * @return string Gallery output.
 */
function ppg_post_gallery( $default, $attr ) {
	if ( isset( $attr['password'] ) && ! empty( $attr['password'] ) && gallery_password_required( $attr['password'] ) ) {
		return ppg_get_the_password_form( md5( serialize( $attr ) ) );
	}
	return $default;
}
add_filter('post_gallery', 'ppg_post_gallery', 199, 2 );

//