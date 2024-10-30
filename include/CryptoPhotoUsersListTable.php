<?php
/*
Plugin Name: CryptoPhoto Users Table
Plugin URI: https://github.com/cryptophoto/cryptophoto_wordpress
Description: This plugin enables CryptoPhoto authentication for WordPress logins.
Version: 1.20130812
Author: CryptoPhoto
Author URI: http://cryptophoto.com
License: GPL2
*/

if( ! class_exists( 'WP_List_Table' ) ) {
    require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
}

class CP_Users_List_Table extends WP_List_Table {

  var $res = null;
  var $num_rows = null;
  var $filter = null;

  // constructor
  function __construct($res, $num_rows, $filter) {
    global $status, $page;
    global $wpdb;
    $this->filter = $filter;

    parent::__construct( array(
        'singular'  => __( 'user', 'usersListTable' ),     //singular name of the listed records
        'plural'    => __( 'users', 'usersListTable' ),   //plural name of the listed records
        'ajax'      => false                               //does this table support ajax?
    ) );
    add_action( 'admin_head', array( &$this, 'admin_header' ) );            
  }


  // generate the table header
  function admin_header() {
    $page = ( isset($_GET['page'] ) ) ? esc_attr( $_GET['page'] ) : false;
    if( 'cp_users_list' != $page )
      return;
    echo '<style type="text/css">';
    echo '.wp-list-table .column-id { width: 15%; }';
    echo '.wp-list-table .column-user_nicename { width: 20%; }';
    echo '.wp-list-table .column-user_login { width: 20%; }';
    echo '.wp-list-table .column-cryptophoto { width: 15%; }';
    echo '.wp-list-table .column-user_email { width: 30%;}';
    echo '</style>';
  }


  // message to be displayed when there are no items found
  function no_items() {
    _e( 'No users were found.' );
  }


  // update method
  function update_items() {
    $this->items = $this->res;
  }


  function column_default( $item, $column_name ) {
    switch( $column_name ) { 
      case 'user_login':
      case 'cyptophoto':
      case 'user_email':
      case 'user_nicename':
      case 'cryptophoto':
      case 'id':
          return isset($item[$column_name]) ? $item[ $column_name ] : 0;
      default:
          return print_r( $item, true ) ; //Show the whole array for troubleshooting purposes
    }
  }


  // sets the sortable columns of the table
  function get_sortable_columns() {
    $sortable_columns = array(
      'id'  => array('id', false),
      'user_nicename' => array('user_nicename', false),
      'user_login' => array('user_login', false),
      'user_email' => array('user_email', false),
    );
    return $sortable_columns;
  }

  // gets a list of columns
  function get_columns(){
    $columns = array(
        'cb'        => '<input type="checkbox" />',
        'id'    => __( 'User Id', 'usersListTable' ),
        'user_nicename' => __( 'User Nicename', 'usersListTable' ),
        'cryptophoto' => __( 'Cryptophoto', 'usersListTable' ),
        'user_login'    => __( 'User Login', 'usersListTable' ),
        'user_email'      => __( 'Email', 'usersListTable' ),
    );
    return $columns;
  }


  // handles the sorting direction
  function usort_reorder( $a, $b ) {
    // If no sort, default to title
    $orderby = ( ! empty( $_GET['orderby'] ) ) ? $_GET['orderby'] : 'id';

    // If no order, default to asc
    $order = ( ! empty($_GET['order'] ) ) ? $_GET['order'] : 'asc';

    // Determine sort order
    $result = strcmp( $a[$orderby], $b[$orderby] );

    // Send final sort direction to usort
    return ( $order === 'asc' ) ? $result : -$result;
  }


  function column_id($item){
    $actions = array(
      'edit'      => sprintf('<a href="user-edit.php?user_id=%s">Edit</a>',$item['id']),
    );
    return sprintf('%1$s %2$s', $item['id'], $this->row_actions($actions) );
  }


  // define the bulk options
  function get_bulk_actions() {
    $actions = array(
      'disable'  => 'Disable',
      'enable'    => 'Enable'
    );
    return $actions;
  }


  // generate the checkbox column
  function column_cb($item) {
    return sprintf(
      '<input type="checkbox" name="user[]" value="%s" />', $item['id']
    );    
  }


  // prepares the list of items for displaying
  function prepare_items($per_page = 10) {
    global $wpdb;
    
    $filter = "";
    if ($this->filter) {
      $filter = " " . $this->filter;
    }

    $current_page = $this->get_pagenum();

    $sql_query = "SELECT id, user_nicename, user_login, user_email, user_status FROM ".$wpdb->users. $filter . 
                 " LIMIT " . ( ( $current_page-1 ) * $per_page ) . "," . $per_page;

    $this->res = $wpdb->get_results($sql_query, ARRAY_A);
    usort( $this->res, array( &$this, 'usort_reorder' ) );

    $columns  = $this->get_columns();
    $hidden  = array();
    $sortable = $this->get_sortable_columns();
    $this->_column_headers = array( $columns, $hidden, $sortable );

    $total_items = $wpdb->get_results("SELECT COUNT(id) FROM ".$wpdb->users. $filter, ARRAY_N);
    $total_items = $total_items[0][0];

    $this->found_data = $this->res;
    $this->set_pagination_args( array(
      'total_items' => $total_items,                // calculate the total number of items
      'per_page'    => $per_page                    // determine how many items to show on a page
    ) );
    $this->items = $this->found_data;
  }


  // method to write messages to the WP error log
  function write_log($msg) {
    error_log($msg . "\n", 3, "/home/t2test/public_html/wordpress/wordpress/error_log");
  }

} //class

//------------------------------------------------------------------------------------------------------------------------------------------
