<?php

const Ranges_Dont_Intersect = -1; //            a=10.0.0.0/24,              b=192.168.0.0/24,
const Ranges_Intersect = 10;      //            a=10.0.0.10-10.0.0.0.20     b=10.0.0.5-10.0.0.0.15
//const AisPartiallyInBLow = 11;    //            a=10.0.0.1-10.0.0.0.10      b=10.0.0.5-10.0.0.0.15
//const AisPartiallyInBHigh = 12;   //            a=10.0.0.10-10.0.0.0.20     b=10.0.0.5-10.0.0.0.15
const RangeB_Contains_RangeA = 1; //A is in B            a=10.0.1.0/24               b=10.0.0.0/16
const RangeA_Contains_RangeB = 2; //B is in A            a=10.0.0.0/16               b=10.0.1.0/24

//const AltB = -2; //A is smaller than B  a=10.0.0.0/24,              b=192.168.0.0/24,
//const AgtB = 3; //A is bigger than B   a=192.168.0.0/24,           b=10.0.0.0/24,


class Expression
{

    /***
     * Converts a JSON expressed object expression into a string , for instance, to place in the config XML
     * @return string
     */
    public static function expressionString2Json():string{
        return '';
    }

    /***
     * Converts a string object expression into a JSON expression to be able to calculate its values
     * @param string $expression
     * @return string
     */
    public static function expressionJson2String(string $expression):string{
        return self::expressionInterpreter(json_decode($expression, true));
    }

    /***
     * @param array $expression
     * @return string
     */
    private static function expressionInterpreter(array $expression):string{
        if(!isset($expression['operator'])){
            return "'".$expression[0]."'";
        }

        $operator = (string) $expression['operator'];
        if(isset($expression['operand1'])){
            $operands[] = $expression['operand1'];
        }
        if(isset($expression['operand2'])){
            $operands[] = $expression['operand2'];
        }

        switch($operator){
            case '∩':
                if(count($operands)!==2){
                    echo "Intersection requires two operands";
                }
                return "(".self::expressionInterpreter($operands[1])." ∩ ".self::expressionInterpreter($operands[0]).")";

            case '~':
                if(count($operands)!==1){
                    echo "Negation requires two operands";
                }
                return "(~".self::expressionInterpreter($operands[0]).")";

            case '∪':
                if(count($operands)!==2){
                    echo "Union requires two operands";
                }
                return "(".self::expressionInterpreter($operands[1])." ∪ ".self::expressionInterpreter($operands[0]).")";

            default:
                return "'".$expression[0]."'";
        }
    }


    /***
     * Given a JSON for an expression, returns an array of all the objects being used
     * @param string $expresison
     * @return array
     */
    public static function getReferredObjects(string $expresison):array{
        return self::getObjectsInExpression(json_decode($expresison, true));
    }

    /***
     * Recursive analysis of a JSON for an expression, returns an array of all the objects being used
     * @param array $expression
     * @return array
     */
    private static function getObjectsInExpression(array $expression):array{
        if(!isset($expression['operator'])){
            return [$expression[0]=>[]];
        }

        $operator = (string) $expression['operator'];
        if(isset($expression['operand1'])){
            $operands[] = $expression['operand1'];
        }
        if(isset($expression['operand2'])){
            $operands[] = $expression['operand2'];
        }

        switch($operator){
            case '∩':
            case '∪':
                return array_merge(
                    self::getObjectsInExpression($operands[1]),
                    self::getObjectsInExpression($operands[0])
                );

            case '~':
                return self::getObjectsInExpression($operands[0]);

            default:
                return [$expression[0]=>[]];
        }
    }


    /***
     * Compares two array with format ['start'=>int, 'end'=>int] to check which one starts earlier
     * @param $a array
     * @param $b array
     * @return bool
     */
    private static function object_cmp(array $a, array $b):bool{
        return $a['start'] > $b['start'];
    }

    /***
     * @param array $group1 Associative as a set of ['start':int, 'end':int] that represents a set of IP ranges
     * @param array $group2 Associative as a set of ['start':int, 'end':int] that represents a set of IP ranges
     * @return array Associative as a set of ['start':int, 'end':int] that represents the union of IP ranges
     */
    public static function union(array $group1, array $group2):array{
        $union = array_merge($group1, $group2);

        //Sort the elements in the merge by the start value
        usort($union, "Expression::object_cmp");

        return self::reduce($union);
    }



    /***
     * @param $group1 array Associative as a set of ['start':int, 'end':int] that represents a set of IP ranges
     * @return array Associative as a set of ['start':int, 'end':int] that represents the negation of the input IP range
     */
    public static function negate(array $group1): array{
        $fakeMapping[] = array('start' => 0, 'end' => ip2long('255.255.255.255'));
        foreach ($group1 as $entry){
            removeNetworkFromIP4Mapping($fakeMapping, $entry);
        }

        return $fakeMapping;
    }



    /***
     * @param array $group1 Associative as a set of ['start':int, 'end':int] that represents a set of IP ranges
     * @param array $group2 Associative as a set of ['start':int, 'end':int] that represents a set of IP ranges
     * @return array Associative as a set of ['start':int, 'end':int] that represents the intersection of IP ranges
     */
    public static function intersect(array $group1, array $group2):array{
        $crossing = [];

        usort($group1, "Expression::object_cmp");
        usort($group2, "Expression::object_cmp");

        foreach ($group1 as $member_in_a){
            foreach ($group2 as $member_in_b){
                $way = -1;
                $result = self::netMatch2Ways($member_in_a, $member_in_b, $way);
                if($way===RangeB_Contains_RangeA) {
                    $crossing[] = $member_in_a;
                }
                elseif($way===RangeA_Contains_RangeB) {
                    $crossing[] = $member_in_b;
                }
                elseif($way===Ranges_Intersect) {
                    $crossing[] = [
                        'start' => $result['start'],
                        'end' => $result['end']
                    ];
                }
            }
        }

        return $crossing;
    }


    /***
     * @param array $range_1
     * @param array $range_2
     * @param int $way
     * @return array
     */
    private static function netMatch2Ways(array $range_1, array $range_2, int &$way):array{
        //Invalid addresses found
        if($range_1['start']<0 || $range_2['start']<0 || $range_1['end']<0 || $range_2['end']<0){
            $way=Ranges_Dont_Intersect;
            return [];
        }


        //Calculate overlapping
        if ($range_1['start'] >= $range_2['start'] && $range_1['end'] <= $range_2['end']) {
            $way=RangeB_Contains_RangeA;
            return $range_1;
        }
        if ($range_1['start'] >= $range_2['start'] && $range_1['start'] <= $range_2['end']){
            $a['start']= $range_1['start'];
            $a['end']= $range_2['end'];
            $way=Ranges_Intersect;
            return $a;
        }
        if($range_1['end'] >= $range_2['start'] && $range_1['end'] <= $range_2['end']) {
            $a['start']=$range_2['start'];
            $a['end']=$range_1['end'];
            $way=Ranges_Intersect;
            return $a;
        }
        if ($range_1['start'] <= $range_2['start'] && $range_1['end'] >= $range_2['end']){
            $way=RangeA_Contains_RangeB;
            return $range_2;
        }
        $way=Ranges_Dont_Intersect;
        return [];
    }


    /***
     * @param array $range
     * @return array
     */
    private static function reduce(array $range):array{
        $result = [];

        //Fuse members that are contiguos or are overlapping
        $first_element = $range[0];
        for($i=1, $iMax = count($range); $i< $iMax; $i++){
            $second_element = $range[$i];

            if(($first_element['end']+1)<$second_element['start']){ // The first element does not intersect with the second element
                $result[] = $first_element;
                $first_element = $second_element;
                continue;
            }

            if($first_element['end'] > $second_element['end']){ //First element already covers the whole second element
                continue;
            }

            if($first_element['end']< $second_element['end']){  //The elements intersect or they are contiguous
                $first_element['end'] = $second_element['end'];
            }
        }

        if($first_element !== []) {
            $result[] = $first_element;
        }

        return $result;
    }

    /***
     * Gets an array representing a range with ['start':int, 'end':int] and converts it into an address or range representation
     * @param array $member
     * @return array [type:string, value:array['start', 'end']]
     */
    public static function toRange(array $member):array{
        if($member['start'] === $member['end']){
            return [
                'ip-netmask',
                long2ip($member['start'])
            ];
        }

        return [
            'ip-range',
            long2ip($member['start'])."-".long2ip($member['end'])];
    }
}