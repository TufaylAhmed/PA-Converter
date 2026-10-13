<?php

require '/var/www/html/libs/objects/tools/expressions/Expression.php';

$group1 =[
    ['start'=>40, 'end'=>47],
    ['start'=>5, 'end'=>12]
];

$group2 = [
];

$expression1_json = '{"operator":"~","operand1":{"0":"Shared Domain- iNET_INTEL"}}';
$expression2_json = '{"operator":"\u2229","operand1":{"0":"Shared Domain- iNET_INTEL"},"operand2":{"operator":"~","operand1":{"operator":"\u222a","operand1":{"0":"Shared Domain- g_pub_INTEL-NETWORKS-PUBLIC-ACCESSIBLE (Get approval to use)"},"operand2":{"0":"Shared Domain- g_dmz_ALL-NETS"}}}}';

function test_union_1($group1, $group2)
{
    $union = Expression::union($group1, $group2);
    echo "Union:";
    print_r($union);
}

function test_intersect_1($group1, $group2)
{
    $union = Expression::intersect($group1, $group2);
    echo "Intersection:";
    print_r($union);
}

function json_to_string_1($express)
{
    return Expression::expressionJson2String($express);
}

echo "result: ".json_to_string_1($expression2_json)."\n";
//test_union_1($group1, $group2);

print_r(Expression::getReferredObjects($expression2_json));
