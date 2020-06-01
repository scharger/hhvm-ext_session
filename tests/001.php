<?hh // partial

echo "Check:\n";
echo "\text_session extension loaded: ";
if (extension_loaded("ext_session")) {
	echo "yes\n";
	echo "\t\tsession_start function exists: ";
	if (function_exists("session_start")) {
		echo "yes\n";
	} else {
			echo "no\n";
	}
} else {
		echo "no\n";
}