#mongo_path='/tools/mongodb/mongodb-osx-x86_64-2.6.3/bin/'
mongo_path='/app/mongo/mongodb-linux-x86_64-3.0.1'
dir='/app/build/source/faceye-security/faceye-security-manager-mongo'
#dir='/work/Work/FeatureWorkSpace/feature/faceye-security/faceye-security-manager-mongo'
db=cms
#cd /tools/mongodb/mongodb-osx-x86_64-3.0.1/bin
cd /app/mongo/mongodb-linux-x86_64-3.0.1/bin
#cd /app/mongo/mongodb-linux-x86_64-3.0.1/bin
./mongoimport -d $db -c security_role $dir/data/init/security_role
./mongoimport -d $db  -c security_user  $dir/data/init/security_user
./mongoimport -d $db -c security_resource  $dir/data/init/security_resource
./mongoimport -d $db -c security_menu  $dir/data/init/security_menu
